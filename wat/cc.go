package wat

import (
	"sync/atomic"
	"time"
)

// lossAwareOn enables the loss-aware ceiling (opt-in, -loss-ceiling). Off by default: judged per 50 ms tick it also
// reacts to a local datagram flood's own drops and to CPU-starved receivers, which the delay rule handles better.
var lossAwareOn atomic.Bool

// SetLossCeiling switches the loss-aware ceiling on or off for every session of this process.
func SetLossCeiling(on bool) { lossAwareOn.Store(on) }

// cc is a delay-based pacer. Random loss on this path is ~0.2-2% and says nothing about congestion, so loss
// never changes the rate; only a growing RTT (a queue building somewhere) slows it down.
type cc struct {
	rate, maxRate, minRate float64 // bytes per second
	tokens                 float64
	slack                  time.Duration

	minRTT   time.Duration
	minRTTAt time.Time
	srtt     time.Duration
	rttvar   time.Duration
	latest   time.Duration

	tickAt   time.Time
	rttSum   time.Duration
	rttN     int
	limited  bool
	maxPlain int // plaintext bytes per datagram (cwnd floor is 40 of them)
	backoff  int // consecutive inflated intervals (for stats)

	// reliable: the carrier is TCP based (Profile.Reliable). It never loses a datagram by itself, but a lost TCP
	// segment stalls one connection for 1-2 RTT (head-of-line), so a few samples per interval are late while the
	// rest are on time. Judging delay by the interval's floor instead of its mean, and giving loss detection the
	// time a TCP retransmit takes, keeps the pacer and the repair logic from reacting to that (measured 2026-10-09
	// on the bench link: 56 % of all packets were spurious retransmits).
	reliable bool
	tickMin  time.Duration

	pathRTT time.Duration // bond: the slowest recently used path's RTT, so the window covers every path

	// Loss-aware soft ceiling (v1.8.0). Loss alone is not congestion here (~0.2 % random), but a loss rate far above
	// the learned baseline means the path is dropping our packets at a bottleneck (measured 2026-10-10: past ~50k
	// pps a deep queue fills and 30 % of the wire was retransmissions). Then the rate is cut and may not climb past a
	// ceiling that itself only creeps up while no loss is seen.
	sentN, lostN int     // tracked packets sent / declared lost in the current tick
	baseLoss     float64 // learned quiet-interval loss (EWMA, floor minBaseLoss)
	lossPct      float64 // last judged interval's loss, 0..1 (stats)
	ceiling      float64 // bytes per second; 0 = none
}

const (
	minBaseLoss   = 0.005
	lossFloor     = 0.03
	lossMinSent   = 50
	lossCut       = 0.85
	ceilingHead   = 1.05
	ceilingGrowth = 1.02
)

// lossLimit is the interval loss above which the path counts as dropping our packets.
func (c *cc) lossLimit() float64 {
	b := c.baseLoss
	if b < minBaseLoss {
		b = minBaseLoss
	}
	return max(lossFloor, 4*b)
}

// lossStep judges one tick's loss; true when the rate was just cut.
func (c *cc) lossStep() bool {
	sent, lost := c.sentN, c.lostN
	c.sentN, c.lostN = 0, 0
	if c.reliable || sent < lossMinSent || !lossAwareOn.Load() {
		return false
	}
	loss := float64(lost) / float64(sent)
	c.lossPct = loss
	if loss > c.lossLimit() {
		c.rate *= lossCut
		if c.rate < c.minRate {
			c.rate = c.minRate
		}
		c.ceiling = c.rate * ceilingHead
		return true
	}
	c.baseLoss += (loss - c.baseLoss) / 64
	if c.baseLoss < minBaseLoss {
		c.baseLoss = minBaseLoss
	}
	if c.ceiling > 0 {
		c.ceiling *= ceilingGrowth
		if c.ceiling >= c.maxRate {
			c.ceiling = 0
		}
	}
	return false
}

func newCC(initRate, minRate, maxRate float64, slack time.Duration) cc {
	return cc{rate: initRate, minRate: minRate, maxRate: maxRate, slack: slack}
}

func (c *cc) refill(dt time.Duration) {
	c.tokens += c.rate * dt.Seconds()
	if max := c.rate*0.012 + 4000; c.tokens > max {
		c.tokens = max
	}
}

func (c *cc) sample(rtt time.Duration, now time.Time) {
	if rtt <= 0 {
		return
	}
	c.latest = rtt
	if c.srtt == 0 {
		c.srtt, c.rttvar = rtt, rtt/2
	} else {
		d := c.srtt - rtt
		if d < 0 {
			d = -d
		}
		c.rttvar = (3*c.rttvar + d) / 4
		c.srtt = (7*c.srtt + rtt) / 8
	}
	if c.minRTT == 0 || rtt < c.minRTT || now.Sub(c.minRTTAt) > 10*time.Second {
		c.minRTT, c.minRTTAt = rtt, now
	}
	c.rttSum += rtt
	if c.rttN == 0 || rtt < c.tickMin {
		c.tickMin = rtt
	}
	c.rttN++
}

// tick runs every ~50 ms.
func (c *cc) tick(now time.Time) {
	if now.Sub(c.tickAt) < 50*time.Millisecond {
		return
	}
	c.tickAt = now
	cut := c.lossStep()
	if c.rttN > 0 && c.minRTT > 0 {
		avg := c.rttSum / time.Duration(c.rttN)
		if c.reliable {
			avg = c.tickMin
		}
		slack := c.slack
		if s := c.minRTT / 8; s > slack {
			slack = s
		}
		if avg > c.minRTT+slack {
			c.rate *= 0.93
			if c.rate < c.minRate {
				c.rate = c.minRate
			}
			c.backoff++
		} else {
			c.backoff = 0
			if c.limited && !cut {
				c.rate *= 1.10
				if c.ceiling > 0 && c.rate > c.ceiling {
					c.rate = max(c.ceiling, c.rate/1.10) // never raise past the ceiling
				}
				if c.rate > c.maxRate {
					c.rate = c.maxRate
				}
			}
		}
	}
	c.rttSum, c.rttN, c.limited = 0, 0, false
}

func (c *cc) cwnd() int {
	rtt := c.srtt
	if c.pathRTT > rtt {
		rtt = c.pathRTT
	}
	if rtt == 0 {
		rtt = 100 * time.Millisecond
	}
	return int(c.rate*rtt.Seconds()*2) + 40*c.maxPlain
}

// pto is how long an unacknowledged packet may stay out before it is presumed lost.
func (c *cc) pto() time.Duration {
	d := 3*c.srtt + 4*c.rttvar
	if d < 120*time.Millisecond {
		d = 120 * time.Millisecond
	}
	if c.reliable && d < reliablePTO {
		d = reliablePTO
	}
	return d
}

func (c *cc) lossTime() time.Duration {
	rtt := c.srtt
	if c.latest > rtt {
		rtt = c.latest
	}
	d := rtt + rtt/4 + 3*time.Millisecond
	if c.reliable && d < reliableLossTime {
		d = reliableLossTime
	}
	return d
}

// A reliable carrier's datagram is late, not lost: TCP's own retransmit timer is at least 200 ms. These floors
// only matter when a connection died (its queue is gone) or a bounded queue overflowed.
const (
	reliablePTO      = 500 * time.Millisecond
	reliableLossTime = 400 * time.Millisecond
)

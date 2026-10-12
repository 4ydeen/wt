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
	hardMin      float64 // the configured floor; minRate may sit above it (reliable: the start rate)
	lowTicks     int     // reliable: ticks left during which overload may cut below minRate, down to hardMin
	stuckTicks   int     // reliable: loss cuts while already at the floor (reset once the rate climbs)
	lossOff      int     // reliable: ticks left during which loss is not treated as overload
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
	if c.reliable {
		return c.reliableLoss(sent, lost)
	}
	if sent < lossMinSent || !lossAwareOn.Load() {
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

// A reliable carrier loses a datagram only when it sat in some queue past reliableLossTime, or its connection died.
// Many of those in one tick mean the path is far slower than our pace: a CDN edge buffering for a slow last leg
// (field 2026-10-12, wss via Cloudflare: four sessions held at the 8 MB/s floor into a ~10 MB/s path, 10 MB in
// flight, sustained download collapsed from 40-50 to 10 MB/s with ~500 ms stalls). Retransmitted packets give no RTT
// sample, so the delay rule cannot see that queue. Cut, and for a while let the rate fall below the start-rate floor.
const (
	relLossMin  = 4  // lost packets in one tick
	relLossFrac = 20 // and at least 1/20 of the tick's sent packets
	relLossCut  = 0.8
	relLowTicks = 600 // ~30 s at 50 ms per tick, renewed by every cut

	// Loss that goes on while the rate sits at the floor was not caused by our rate (field 2026-10-12, 2.4.6 after
	// ~3 h: a few CDN connections delivered seconds late, half of all packets were resent, and every session sat at
	// the 0.2 MB/s floor for good because each tick at the floor still saw losses). After relStuckTicks such cuts
	// the loss rule stands down for relLossOff ticks and the delay rule alone sets the pace.
	relStuckTicks = 40  // >= 2 s of cuts at the floor
	relLossOff    = 600 // ~30 s
)

func (c *cc) reliableLoss(sent, lost int) bool {
	if c.lowTicks > 0 {
		c.lowTicks--
	}
	if sent+lost >= lossMinSent { // judged intervals only, like the datagram rule (2.4.2 kept a stale value)
		c.lossPct = float64(lost) / float64(max(sent, lost))
	}
	atFloor := c.rate <= 1.5*c.hardMin
	if !atFloor {
		c.stuckTicks = 0
	}
	if c.lossOff > 0 {
		c.lossOff--
		return false
	}
	if lost < relLossMin || lost*relLossFrac < sent {
		return false
	}
	if atFloor {
		if c.stuckTicks++; c.stuckTicks >= relStuckTicks {
			c.stuckTicks, c.lossOff, c.lowTicks = 0, relLossOff, 0
			return false
		}
	}
	c.rate *= relLossCut
	if c.rate < c.hardMin {
		c.rate = c.hardMin
	}
	c.lowTicks = relLowTicks
	return true
}

// floor is the lowest rate the delay rule may cut to.
func (c *cc) floor() float64 {
	if c.lowTicks > 0 {
		return c.hardMin
	}
	return c.minRate
}

func newCC(initRate, minRate, maxRate float64, slack time.Duration) cc {
	return cc{rate: initRate, minRate: minRate, hardMin: minRate, maxRate: maxRate, slack: slack}
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
		// reliable (TCP pool, e.g. through a CDN): delay spread across edges and TCP buffering inflates the RTT
		// without any queue of ours, and real congestion is already handled by TCP. Allow a third of the RTT and cut
		// only while we fill the window ourselves: in production (2.4.0, ~500 bursty web streams) the old rule cut
		// app-limited sessions down to the 0.2 MB/s floor and they never climbed back.
		if c.reliable {
			if s := c.minRTT / 3; s > slack {
				slack = s
			}
		}
		// reliable: even the interval's fastest sample at twice the base RTT is our own queue, not edge spread, so the
		// cut may go under the start-rate floor (field 2026-10-12: a ~10 MB/s CDN leg under a 4 x 8 MB/s floor queued
		// until packets timed out).
		if c.reliable && c.limited && avg > 2*c.minRTT && avg-c.minRTT > 40*time.Millisecond {
			c.lowTicks = relLowTicks
		}
		if avg > c.minRTT+slack && (!c.reliable || c.limited) {
			c.rate *= 0.93
			if f := c.floor(); c.rate < f {
				c.rate = min(f, c.rate/0.93) // clamp to the floor, but never raise a rate already below it
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
	// reliable: srtt includes our own queue in the TCP buffers, so a window sized from it grows with the queue it
	// creates and the sender is never window-limited. Size it from the base RTT instead.
	if c.reliable && c.minRTT > 0 {
		if lim := c.minRTT + c.minRTT/2; rtt > lim {
			rtt = lim
		}
	}
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

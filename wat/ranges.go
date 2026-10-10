package wat

import "sort"

// rng is a half-open interval [lo, hi).
type rng struct{ lo, hi uint64 }

// rangeSet is a sorted list of disjoint, non-adjacent intervals.
type rangeSet []rng

func (r *rangeSet) add(lo, hi uint64) {
	if hi <= lo {
		return
	}
	s := *r
	i := sort.Search(len(s), func(i int) bool { return s[i].hi >= lo })
	j := i
	for j < len(s) && s[j].lo <= hi {
		if s[j].lo < lo {
			lo = s[j].lo
		}
		if s[j].hi > hi {
			hi = s[j].hi
		}
		j++
	}
	if i == j {
		s = append(s, rng{})
		copy(s[i+1:], s[i:])
		s[i] = rng{lo, hi}
	} else {
		s[i] = rng{lo, hi}
		s = append(s[:i+1], s[j:]...)
	}
	*r = s
}

func (r rangeSet) contains(x uint64) bool {
	i := sort.Search(len(r), func(i int) bool { return r[i].hi > x })
	return i < len(r) && r[i].lo <= x
}

// covered reports whether all of [lo, hi) is inside the set.
func (r rangeSet) covered(lo, hi uint64) bool {
	if hi <= lo {
		return true
	}
	i := sort.Search(len(r), func(i int) bool { return r[i].hi > lo })
	return i < len(r) && r[i].lo <= lo && r[i].hi >= hi
}

// trim drops everything below keep, leaving at most n newest intervals.
func (r *rangeSet) trim(n int) {
	if len(*r) > n {
		*r = append((*r)[:0], (*r)[len(*r)-n:]...)
	}
}

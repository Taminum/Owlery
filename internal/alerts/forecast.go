package alerts

import (
	"math"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

const (
	// forecastMinSpan and forecastMinPoints: less history than this says nothing about a trend.
	forecastMinSpan   = 24 * time.Hour
	forecastMinPoints = 12
	// forecastMinFit is how well a straight line must fit the week for the forecast to be believed: a disk that fills and
	// empties again (log rotation, a nightly backup) has no "days left".
	forecastMinFit = 0.6
	// forecastMinGrowth is the least growth per day, as a share of the disk, worth forecasting from: under it a slope is noise.
	forecastMinGrowth = 0.001
	// HostDiskForecastDays: a disk that will be full within this many days is reported before it is nearly full.
	HostDiskForecastDays = 14
)

// DiskDaysLeft says in how many days a disk will be full if it goes on growing the way the last days show, from hourly
// readings of how much is used. ok is false when there is too little history, the disk is not growing, or the growth is
// not steady enough to extend.
func DiskDaysLeft(points []store.DiskPoint, total int64) (days, perDay float64, ok bool) {
	if total <= 0 || len(points) < forecastMinPoints || points[len(points)-1].At.Sub(points[0].At) < forecastMinSpan {
		return 0, 0, false
	}
	t0 := points[0].At
	var sx, sy, sxx, sxy, syy float64
	n := float64(len(points))
	for _, p := range points {
		x := p.At.Sub(t0).Hours() / 24
		y := float64(p.Used)
		sx, sy, sxx, sxy, syy = sx+x, sy+y, sxx+x*x, sxy+x*y, syy+y*y
	}
	dx := n*sxx - sx*sx
	dy := n*syy - sy*sy
	if dx <= 0 || dy <= 0 {
		return 0, 0, false
	}
	slope := (n*sxy - sx*sy) / dx // bytes per day
	r := (n*sxy - sx*sy) / math.Sqrt(dx*dy)
	if slope < forecastMinGrowth*float64(total) || r*r < forecastMinFit {
		return 0, 0, false
	}
	free := float64(total - points[len(points)-1].Used)
	if free <= 0 {
		return 0, slope, true
	}
	return free / slope, slope, true
}

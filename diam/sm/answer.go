package sm

import "github.com/gomaja/go-diameter/diam"

func connectionGeneration(c diam.Conn) uint64 {
	if lifecycle, ok := diam.ConnAs[diam.ConnLifecycle](c); ok {
		return lifecycle.Generation()
	}
	return 0
}

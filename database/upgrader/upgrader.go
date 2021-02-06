// Copyright (c) 2014-2019 Ludovic Fauvet
// Licensed under the MIT license

package upgrader

import (
	"github.com/xbmc/mirrorbits/database/interfaces"
	v1 "github.com/xbmc/mirrorbits/database/v1"
)

// Upgrader is an interface to implement a database upgrade strategy
type Upgrader interface {
	Upgrade() error
}

// GetUpgrader returns the upgrader for the given target version
func GetUpgrader(redis interfaces.Redis, version int) Upgrader {
	switch version {
	case 1:
		return v1.NewUpgraderV1(redis)
	}
	return nil
}

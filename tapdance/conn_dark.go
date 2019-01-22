package tapdance

import (
	"context"
	"net"
	"time"
)


func dialDarkDecoy(ctx context.Context, tdFlow *TapdanceFlowConn) (net.Conn, error) {
	_ddIpSelector, err := newDDIpSelector([]string{"192.122.190.0/24", "2001:48a8:8000::/33"})
//	_ddIpSelector, err := newDDIpSelector([]string{"192.122.190.0/24"})
	if err != nil {
		return nil, err
	}

	tdFlow.tdRaw.tagType = tagHttpGetComplete
	tdFlow.flowType = flowRendezvous

	err = tdFlow.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	go readAndClose(tdFlow, time.Second * 15)

	darDecoyIpAddr, err := _ddIpSelector.selectIpAddr(tdFlow.tdRaw.tdKeys.DarkDecoySeed)
	if err != nil {
		Logger().Infof( "%v failed to select dark decoy: %v\n", tdFlow.idStr(), err)
		return nil, err
	}

	getRttMillisec := func() int {
		defaultValue := 300
		if tdFlow == nil {
			return defaultValue
		}
		if tdFlow.tdRaw == nil {
			return defaultValue
		}
		if tdFlow.tdRaw.sessionStats.TcpToDecoy == nil {
			return defaultValue
		}
		return int(*tdFlow.tdRaw.sessionStats.TcpToDecoy)
		}
	// randomized sleeping here to break the intraflow signal
	toSleep := time.Millisecond * time.Duration(300 + getRttMillisec() * getRandInt(0, 3449) / 1000)
	Logger().Debugf("%v Registration for dark decoy sent, sleeping for %v", tdFlow.idStr(), toSleep)

	darkDecoy := net.JoinHostPort(darDecoyIpAddr.String(), "443")
	Logger().Infof(  "%v Connecting to dark decoy %v", tdFlow.idStr(), darkDecoy)
	return net.DialTimeout("tcp", darkDecoy, 10 * time.Second)
}

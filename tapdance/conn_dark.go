package tapdance

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/refraction-networking/gotapdance/getifaddr"
)

func dialDarkDecoy(ctx context.Context, tdFlow *TapdanceFlowConn) (net.Conn, error) {

	// Check Ipv6 support
	// 		*bool so that it is a nullable type. that can be overridden by the dialer & tdRawConn
	var ipSupport bool
	if tdFlow.tdRaw.darkDecoyV6Support == true {
		ipSupport = getifaddr.SupportsIpv6()
		tdFlow.tdRaw.darkDecoyV6Support = ipSupport
	} else {
		ipSupport = tdFlow.tdRaw.darkDecoyV6Support
	}

	_ddIpSelector, err := newDDIpSelector([]string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}, ipSupport)
	if err != nil {
		return nil, err
	}

	tdFlow.tdRaw.tagType = tagHttpGetComplete
	tdFlow.flowType = flowRendezvous
	tdFlow.tdRaw.darkDecoyUsed = true

	err = tdFlow.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	go readAndClose(tdFlow, time.Second*15)

	flowIdString := fmt.Sprintf("[Session %v]", strconv.FormatUint(tdFlow.tdRaw.sessionId, 10))
	darkDecoyIpAddr, err := _ddIpSelector.selectIpAddr(tdFlow.tdRaw.tdKeys.DarkDecoySeed)
	if err != nil {
		Logger().Infof("%v failed to select dark decoy: %v\n", tdFlow.idStr(), err)
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
	toSleep := time.Millisecond * time.Duration(300+getRttMillisec()*getRandInt(212, 3449)/1000)
	Logger().Debugf("%v Registration for dark decoy sent, sleeping for %v",
		flowIdString, toSleep)
	time.Sleep(toSleep)

	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		// randomized timeout to Dial dark decoy address
		deadline = time.Now().Add(getRandomDuration(1061*getRttMillisec()*2, 1953*getRttMillisec()*3))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	darkAddr := net.JoinHostPort(darkDecoyIpAddr.String(), "443")
	darkTcpConn, err := (&net.Dialer{}).DialContext(childCtx, "tcp", darkAddr)
	if err != nil {
		Logger().Infof("%v failed to dial dark decoy %v: %v\n",
			flowIdString, darkDecoyIpAddr.String(), err)
		return nil, err
	}
	Logger().Infof("%v Connected to dark decoy %v", flowIdString, darkAddr)

	return darkTcpConn, nil
}

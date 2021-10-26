package iputil

import (
	"errors"
	"fmt"
	"github.com/d1937/logger"
	"net"
)

// IsCidr determines if the given ip is a cidr range
func IsCidr(ip string) bool {
	_, _, err := net.ParseCIDR(ip)

	return err == nil
}

func IpCidrContains(ip string, cidr string) bool {

	if !IsIP(ip) {
		return false
	}

	_, ips, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	if ips.Contains(net.ParseIP(ip)) {
		return true
	}

	return false
}

/*
CIDR
x.0.0.0/y   -> 192.0.0.0/24
x.0.0.0/y   -> 10.0.0.0/8
x.x.0.0/y   -> 192.168.0.0/16
x.x.x.0/y   -> 192.168.0.0/24
*/
func Ips(cidr string) ([]string, error) {
	inc := func(ip net.IP) {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

// IsIP determines if the given string is a valid ip
func IsIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func ToCidr(item string) *net.IPNet {
	if IsIP(item) {
		item += "/32"
	}
	if IsCidr(item) {
		_, ipnet, _ := net.ParseCIDR(item)
		return ipnet
	}
	return nil
}

func Host2ips(target string) (targetIPs []string, err error) {
	// If the host is a Domain, then perform resolution and discover all IP
	// addresses for a given host. Else use that host for port scanning
	if net.ParseIP(target) == nil {
		var ips []net.IP
		ips, err = net.LookupIP(target)
		//fmt.Println(target,ips)
		if err != nil {
			logger.Warningf("Could not get IP for host: %s\n", target)
			return
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				targetIPs = append(targetIPs, ip.String())
			}
		}

		if len(targetIPs) == 0 {
			return targetIPs, fmt.Errorf("no IP addresses found for host: %s", target)
		}
	} else {
		targetIPs = append(targetIPs, target)
		logger.Debugf("Found %d addresses for %s\n", len(targetIPs), target)
	}

	return
}

func GetDomainIP(host string) (string, error) {

	ips, err := Host2ips(host)

	//fmt.Println(ips)
	if err != nil {
		return "", err
	}

	var (
		initialHosts []string
		hostIP       string
	)

	for _, ip := range ips {

		initialHosts = append(initialHosts, ip)
	}
	//fmt.Println(initialHosts)
	if len(initialHosts) == 0 {
		return "", errors.New("get ip err")
	}
	hostIP = initialHosts[0]

	return hostIP, nil
}

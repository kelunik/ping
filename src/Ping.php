<?php

namespace Kelunik\Ping;

use Amp\Deferred;
use Amp\Dns\Record;
use Amp\Failure;
use Amp\Pause;

class Ping {
    public function ping($host, $sequenceNumber = 1) {
        $fn = function () use ($host, $sequenceNumber) {
            $deferred = new Deferred;
            $start = microtime(1);
            $readBuffer = "";

            $resolved = false;

            $socket = socket_create(AF_INET, SOCK_RAW, getprotobyname("icmp"));

            if (!$socket) {
                $error = socket_last_error();
                return new Failure(new PingException("Unable to create socket ({$error}): " . socket_strerror($error)));
            }

            if ($inAddr = @\inet_pton($host)) {
                $isIpv6 = isset($inAddr[15]);
            } else {
                $records = (yield \Amp\Dns\resolve($host));
                list($host, $mode) = $records[0];
                $isIpv6 = $mode === Record::AAAA;
            }

            $package = $this->buildPingRequest($sequenceNumber);

            socket_connect($socket, $isIpv6 ? "[{$host}]" : $host, null);
            socket_set_nonblock($socket);
            socket_send($socket, $package, strlen($package), 0);

            $watcher = \Amp\repeat(function () use ($socket, $start, $deferred, &$readBuffer) {
                $read = socket_read($socket, 255);

                if ($read != "") {
                    list($source) = array_values(unpack("N*", substr($read, 12, 4)));
                    list($dest) = array_values(unpack("N*", substr($read, 16, 4)));

                    $type = ord($read[20]);
                    $code = ord($read[21]);

                    $checksum = substr($read, 22, 2);

                    list($identifier) = array_values(unpack("n*", substr($read, 24, 2)));
                    list($sequence) = array_values(unpack("n*", substr($read, 26, 2)));

                    $data = substr($read, 28);

                    $package = chr($type) . chr($code) . "\0\0" . pack("n", $identifier) . pack("n", $sequence) . $data;
                    $calculatedChecksum = $this->calculateChecksum($package);

                    if ($checksum !== $calculatedChecksum) {
                        $deferred->fail(new PingException("Wrong checksum, got " . bin2hex($checksum) . " but expected " . bin2hex($calculatedChecksum)));
                        return;
                    }

                    if ($type === 8) {
                        return;
                    } else if ($type === 0) {
                        $response = new Response(
                            long2ip($source),
                            long2ip($dest),
                            $sequence,
                            microtime(1) - $start
                        );

                        $deferred->succeed($response);
                    } else if ($type === 3) {
                        $deferred->fail(new PingException("Destination unreachable", $code));
                    } else {
                        $deferred->fail(new PingException("Unexpected response type: " . $type));
                    }
                } elseif (!is_resource($socket) || @feof($socket)) {
                    $deferred->fail(new PingException("Stream closed unexpectedly."));
                }
            }, 50);

            (new Pause(5000))->when(function () use ($watcher, $socket, $deferred, &$resolved) {
                if ($resolved) {
                    return;
                }

                $deferred->fail(new PingException("Timeout, didn't receive a response fast enough."));
            });

            $promise = $deferred->promise();

            $promise->when(function () use ($watcher, $socket, &$resolved) {
                \Amp\cancel($watcher);
                @socket_close($socket);

                $resolved = true;
            });

            return $promise;
        };

        return \Amp\resolve($fn());
    }

    private function buildPingRequest($sequenceNumber) {
        $type = "\x08";
        $code = "\0";
        $checksum = "\0\0";
        $identifier = "\0\0";
        $sequence = pack("n", $sequenceNumber);

        $data = hex2bin("39ec030000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");

        $package = $type . $code . $checksum . $identifier . $sequence . $data;
        $checksum = $this->calculateChecksum($package);
        $package = $type . $code . $checksum . $identifier . $sequence . $data;

        return $package;
    }

    private function calculateChecksum($package) {
        if (strlen($package) % 2) {
            $package .= "\0";
        }

        $words = unpack("n*", $package);
        $checksum = 0;

        foreach ($words as $word) {
            $checksum += $word;

            if ($checksum >> 16) {
                $checksum = ($checksum + 1) & 0xFFFF;
            }
        }

        return pack("n*", ($checksum ^ 0xFFFF) & 0xFFFF);
    }
}
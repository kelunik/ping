<?php

namespace Kelunik\Ping;

use Amp\CoroutineResult;
use Amp\Deferred;
use Amp\Dns\Record;
use Amp\Failure;
use Amp\Pause;

class Ping {
    const TYPE_4_PING_REQUEST = 8;
    const TYPE_4_PING_REPLY = 0;

    const TYPE_6_PING_REQUEST = 128;
    const TYPE_6_PING_REPLY = 129;

    public function ping($host, $sequenceNumber = 1) {
        $fn = function () use ($host, $sequenceNumber) {
            $deferred = new Deferred;
            $start = microtime(1);
            $readBuffer = "";

            $resolved = false;

            if ($inAddr = @\inet_pton($host)) {
                $isIpv6 = isset($inAddr[15]);
            } else {
                $records = (yield \Amp\Dns\resolve($host));
                list($host, $mode) = $records[0];
                $isIpv6 = $mode === Record::AAAA;
            }

            $socket = socket_create($isIpv6 ? AF_INET6 : AF_INET, SOCK_RAW, getprotobyname($isIpv6 ? "ipv6-icmp" : "icmp"));

            if (!$socket) {
                $error = socket_last_error();
                yield new CoroutineResult(new Failure(new PingException("Unable to create socket ({$error}): " . socket_strerror($error))));
                return;
            }

            socket_connect($socket, $host, null);
            socket_set_nonblock($socket);
            socket_getsockname($socket, $sourceIp);

            $sequenceNumber = 1;
            $data = random_bytes(48);

            $package = $isIpv6 ? $this->buildPing6Request($sequenceNumber, $data, $sourceIp, $host) : $this->buildPing4Request($sequenceNumber, $data);

            socket_send($socket, $package, strlen($package), 0);

            $watcher = \Amp\repeat(function () use ($isIpv6, $socket, $start, $deferred, $sourceIp, $host, $data, &$readBuffer) {
                $read = socket_read($socket, 255);

                if ($read != "") {
                    if ($isIpv6) {
                        $source = $host;
                        $dest = $sourceIp;
                        $offset = 0;
                    } else {
                        $source = inet_ntop(substr($read, 12, 4));
                        $dest = inet_ntop(substr($read, 16, 4));
                        $offset = 20;
                    }

                    $type = ord($read[$offset + 0]);
                    $code = ord($read[$offset + 1]);
                    $checksum = substr($read, $offset + 2, 2);
                    $identifier = substr($read, $offset + 4, 2);
                    $sequence = current(unpack("n", substr($read, $offset + 6, 2)));

                    $receivedData = substr($read, $offset + 8);

                    $package = chr($type) . chr($code) . "\0\0" . $identifier . pack("n", $sequence) . $receivedData;

                    if ($isIpv6) {
                        $package = inet_pton($source) . inet_pton($dest) . pack("n", strlen($receivedData) + 8) . "\0\0\0" . chr(58) . $package;
                    }

                    $calculatedChecksum = $this->calculateChecksum($package);

                    if ($checksum !== $calculatedChecksum) {
                        $deferred->fail(new PingException("Wrong checksum, got " . bin2hex($checksum) . " but expected " . bin2hex($calculatedChecksum)));
                        return;
                    }

                    if ($data !== $receivedData) {
                        $deferred->fail(new PingException("Didn't receive sent data.\nSent: '" . bin2hex($data) . "'\nReceived: '" . bin2hex($receivedData) . "'"));
                    }

                    if ((!$isIpv6 && $type === self::TYPE_4_PING_REQUEST) || ($isIpv6 && $type === self::TYPE_6_PING_REQUEST)) {
                        return;
                    } else if ((!$isIpv6 && $type === self::TYPE_4_PING_REPLY) || ($isIpv6 && $type === self::TYPE_6_PING_REPLY)) {
                        $response = new Response(
                            $sourceIp,
                            $host,
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

            yield new CoroutineResult($promise);
            return;
        };

        return \Amp\resolve($fn());
    }

    private function buildPing4Request($sequenceNumber, $data) {
        $type = chr(self::TYPE_4_PING_REQUEST);
        $code = "\0";
        $checksum = "\0\0";
        $identifier = "\0\0";
        $sequence = pack("n", $sequenceNumber);

        $package = $type . $code . $checksum . $identifier . $sequence . $data;
        $checksum = $this->calculateChecksum($package);
        $package = $type . $code . $checksum . $identifier . $sequence . $data;

        return $package;
    }

    private function buildPing6Request($sequenceNumber, $data, $sourceIp, $destIp) {
        $type = chr(self::TYPE_6_PING_REQUEST);
        $code = "\0";
        $checksum = "\0\0";
        $identifier = "\0\0";
        $sequence = pack("n", $sequenceNumber);

        $package = $type . $code . $checksum . $identifier . $sequence . $data;
        $checksum = $this->calculateChecksum(inet_pton($sourceIp) . inet_pton($destIp) . pack("n", strlen($data) + 8) . "\0\0\0" . chr(58) . $package);
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
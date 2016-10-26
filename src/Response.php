<?php

namespace Kelunik\Ping;

class Response {
    private $sourceIp;
    private $destinationIp;

    private $sequenceNumber;
    private $time;

    public function __construct($sourceIp, $destinationIp, $sequenceNumber, $time) {
        $this->sourceIp = $sourceIp;
        $this->destinationIp = $destinationIp;
        $this->sequenceNumber = $sequenceNumber;
        $this->time = $time;
    }

    /**
     * @return string
     */
    public function getSourceIp() {
        return $this->sourceIp;
    }

    /**
     * @return string
     */
    public function getDestinationIp() {
        return $this->destinationIp;
    }

    /**
     * @return int
     */
    public function getSequenceNumber() {
        return $this->sequenceNumber;
    }

    /**
     * @return float
     */
    public function getTime() {
        return $this->time;
    }
}
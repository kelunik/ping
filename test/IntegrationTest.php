<?php

namespace Kelunik\Ping;

class IntegrationTest extends \PHPUnit_Framework_TestCase {
    /** @var Ping */
    private $pingClient;

    protected function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());

        $this->pingClient = new Ping;
    }

    /**
     * @param string $name Name to ping.
     *
     * @group internet
     * @dataProvider providePingNames
     */
    public function testPing($name) {
        $done = false;

        \Amp\run(function () use ($name, &$done) {
            /** @var Response $response */
            $response = (yield $this->pingClient->ping($name));

            $this->assertInstanceOf(Response::class, $response);

            $done = true;

            \Amp\stop();
        });

        $this->assertTrue($done);
    }

    public function providePingNames() {
        return [
            ["google.com"],
            ["github.com"],
            ["localhost"],
            ["127.0.0.1"],
        ];
    }
}
# app_tdd

TDD Module for Asterisk

The goal of app_tdd is to effectively filter out TDD tones coming in on a channel and publish them to AMI/Stasis.  Additionally, allow AMI/Stasis apps to post messages that will in turn be sent out through the channel as TDD tones.

This allows for centralized TDD processing (rather than requiring TDD/TTY hardware or software at the user endpoint).

app_tdd.c contained here compiles cleanly under asterisk 18.8.0.

Things that work so far:

- the receiver does receive TDD (FSK @ 45.45 baud)
- the transmitter does transmit TDD
- both have been tested with real TDD TTY hardware (Ultratec 1140)
- both have been tested with real iPhone RTT (via PSTN)
- AMI events are raised when a TDD message is received
- AMI requests to send TDD on a channel function properly
- CLI requests to send TDD on a channel function properly

Things that still need work:

- rename to TddRx to StartTddRx to better reflect how it works
- add StopTddRx to remove existing TDD processing from a channel
- dialplan APP to send TDD on a channel added, not completely tested
- received messages should be encoded as they may contain control sequences (\r \n \0 etc)
  - some of this is implemented, need to test/complete
- the send AMI and CLI commands should also use some sort of encoding in order to send supported baudot specials
  - some of this is implemented, need to test/complete
- fix AMI/ARI events for TddStop (TddStart is properly emitted)


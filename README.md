# app_tdd

TDD Module for Asterisk

The goal of app_tdd is to effectively filter out TDD tones coming in on a channel and publish them to AMI/Stasis.  Additionally, allow AMI/Stasis apps to post message that will in turn be sent out through the channel as TDD tones.

This allows for centralized TDD processing (rather than requiring TDD/TTY hardware or software at the user endpoint).

Things that work so far:

- the receiver does receive TDD (FSK @ 45.45 baud)
- the transmitter does transmit TDD
- AMI events are raised when a TDD message is received
- AMI requests to send TDD on a channel function properly
- CLI requests to send TDD on a channel function properly

Things that still need work:

- The CLI hangs sometimes, almost certainly because of something I'm doing incorrectly
- Stasis messages posted to the channel topic DO NOT WORK, however I'm still figuring out stasis so again, probablyjust  something I'm doing wrong

app_tdd.c contained here compiles cleanly under asterisk 18.4.0.

/*! \file
 *
 * \brief TddRx() - Technology independent in-line TDD support
 *
 * \ingroup applications
 *
 * \author Darrin M. Gorski <darrin@gorski.net>
 *
 */

/*** MODULEINFO
	<depend>spandsp</depend>
	<support_level>extended</support_level>
 ***/

/* Needed for spandsp headers */
#define ASTMM_LIBC ASTMM_IGNORE

#include "asterisk.h"

#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/audiohook.h"
#include "asterisk/app.h"
#include "asterisk/cli.h"
#include "asterisk/manager.h"
#include "asterisk/json.h"
#include "asterisk/stasis.h"
#include "asterisk/stasis_channels.h"

#define SPANDSP_EXPOSE_INTERNAL_STRUCTURES
#include <spandsp.h>
#include <spandsp/version.h>
#include <spandsp/logging.h>
#include <spandsp/fsk.h>
#include <spandsp/async.h>
#include <spandsp/v18.h>

/*** DOCUMENTATION
	<application name="TddRx" language="en_US">
		<synopsis>
			Enable TDD transmit/receive processing on a channel.
		</synopsis>
		<syntax>
			<parameter name="options">
				<optionlist>
					<option name="b">
						<argument name="bufsiz" required="true">
							<para>Specify a custom input buffer size. This controls received character delivery via manager/stasis events (a smaller value means more messages with less rx chars in each). Valid values are 1-256.</para>
						</argument>
					</option>
					<option name="c">
						<argument name="correlation" required="true">
							<para>Provide a correlation string for this channel, will be sent with TddRxMsg events.</para>
						</argument>
					</option>
					<option name="s">
						<para>Send spaces as underscores in TddRxMsg events.</para>
					</option>
					<option name="m">
						<para>Replace received audio frames with silence while TDD carrier is active.</para>
					</option>
					<option name="i">
						<para>Use International TTY @ 50 bps instead of US TTY @ 45.45.</para>
					</option>
					<option name="w">
						<para>No not continue, wait for channel to hangup or TddStop to disable TDD processing.</para>
					</option>
				</optionlist>
			</parameter>
		</syntax>
		<description>
			<para>The TddRx application is used to begin listening for TDD tones from the channel.  If TDD tones are detected, the received message will be posted via manager/stasis events for this channel.</para>
			<para> </para>
			<para>This application will exit immediately after setting up an audiohook.</para>
		</description>
		<see-also>
			<ref type="application">TddTx</ref>
			<ref type="application">TddWait</ref>
			<ref type="application">TddStop</ref>
			<ref type="manager">TddRx</ref>
		</see-also>
	</application>
	<application name="TddTx" language="en_US">
		<synopsis>
			Send message using TDD tones on the current channel.
		</synopsis>
		<syntax>
			<parameter name="message" required="true" />
		</syntax>
		<description>
			<para>Sends TDD tones to the channel in the same way as the TddTx manager action.</para>
			<para> </para>
			<para>If TDD processing is not enabled via TddRx, will return an error.</para>
		</description>
		<see-also>
			<ref type="application">TddRx</ref>
			<ref type="application">TddStop</ref>
			<ref type="manager">TddTx</ref>
		</see-also>
	</application>
	<application name="TddWait" language="en_US">
		<synopsis>
			Wait for TDD data to finish being sent to a channel.
		</synopsis>
		<syntax>
			<parameter name="message" required="true" />
		</syntax>
		<description>
			<para>This will wait until any pending TDD data has finished being sent to the channel.</para>
			<para>This avoids the need to manually try to calculate the time needed to finish a transmission and wait using an application that passes audio.</para>
		</description>
		<see-also>
			<ref type="application">TddTx</ref>
			<ref type="application">TddStop</ref>
			<ref type="manager">TddTx</ref>
		</see-also>
	</application>
	<application name="TddStop" language="en_US">
		<synopsis>
			Stop TDD processing on a channel.
		</synopsis>
		<syntax>
			<parameter name="message" required="true" />
		</syntax>
		<description>
			<para>This stops TDD processing on a channel if it is no longer necessary, to allow TDD tones to pass through in the audio again.</para>
			<para>TDD processing will need to be enabled again using <literal>TddRx</literal> if it is needed again later.</para>
		</description>
		<see-also>
			<ref type="application">TddRx</ref>
			<ref type="application">TddTx</ref>
			<ref type="manager">TddTx</ref>
			<ref type="manager">TddStop</ref>
		</see-also>
	</application>
	<manager name="TddTx" language="en_US">
		<synopsis>
			Send a TDD message on a channel.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
			<parameter name="Channel" required="true">
				<para>The name of the channel to send on.</para>
			</parameter>
			<parameter name="Message" required="true">
				<para>The message to be sent.</para>
				<para> </para>
				<note><para>TDD uses ITA2_US_TTY (BAUDOT) code which limits the characters that can be sent. Unsupported characters are silently ignored.</para></note>
			</parameter>
		</syntax>
		<description>
			<para>This action sends a message via TDD/TTY tones on the current channel.  If TDD processing is not enabled on the channel an error will be returned.</para>
		</description>
		<see-also>
			<ref type="link">https://en.wikipedia.org/wiki/Baudot_code#ITA_2_and_US-TTY</ref>
		</see-also>
	</manager>
	<manager name="TddStop" language="en_US">
		<synopsis>
			Disable TDD transmit/receive processing on a channel.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
			<parameter name="Channel" required="true">
				<para>The name of the channel to disable TDD processing on.</para>
			</parameter>
		</syntax>
		<description>
			<para>This action is exactly the same as the dialplan application of the same name - it
			disables TDD processing on the specified channel.</para>
		</description>
		<see-also>
			<ref type="application">TddRx</ref>
			<ref type="manager">TddRx</ref>
		</see-also>
	</manager>
	<manager name="TddRx" language="en_US">
		<synopsis>
			Enable TDD transmit/receive processing on a channel.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
			<parameter name="Channel" required="true">
				<para>The name of the channel to enable TDD processing on.</para>
			</parameter>
			<parameter name="Options" required="false">
				<para>Options string, using the same syntax as the TddRx dialplan app.</para>
			</parameter>
		</syntax>
		<description>
			<para>This action is exactly the same as the dialplan command of the same name - it enables TDD processing on the specified channel.</para>
		</description>
		<see-also>
			<ref type="application">TddRx</ref>
		</see-also>
	</manager>
	<managerEvent language="en_US" name="TddRxMsg">
		<managerEventInstance class="EVENT_FLAG_CALL">
			<synopsis>Raised when a TDD message arrives on a channel.</synopsis>
			<syntax>
				<channel_snapshot/>
				<parameter name="Message">
					<para>The TDD message received.</para>
				</parameter>
				<parameter name="Correlation">
					<para>The Tdd instance Correlation value if specified.</para>
				</parameter>
			</syntax>
		</managerEventInstance>
	</managerEvent>
	<managerEvent language="en_US" name="TddStart">
		<managerEventInstance class="EVENT_FLAG_CALL">
			<synopsis>Raised when TDD processing is added to a channel.</synopsis>
		</managerEventInstance>
	</managerEvent>
	<managerEvent language="en_US" name="TddStop">
		<managerEventInstance class="EVENT_FLAG_CALL">
			<synopsis>Raised when TDD processing is removed from a channel.</synopsis>
		</managerEventInstance>
	</managerEvent>
 ***/

/*! \brief for .to_json
 *
 * copied from stasis_channels.c because it's not exposed in .h
 */
static struct ast_json *channel_blob_to_json(
	struct stasis_message *message,
	const char *type,
	const struct stasis_message_sanitizer *sanitize)
{
	struct ast_json *to_json;
	struct ast_channel_blob *channel_blob = stasis_message_data(message);
	struct ast_json *blob = channel_blob->blob;
	struct ast_channel_snapshot *snapshot = channel_blob->snapshot;
	const struct timeval *tv = stasis_message_timestamp(message);
	int res = 0;

	if (blob == NULL || ast_json_is_null(blob)) {
		to_json = ast_json_object_create();
	} else {
		/* blobs are immutable, so shallow copies are fine */
		to_json = ast_json_copy(blob);
	}
	if (!to_json) {
		return NULL;
	}

	res |= ast_json_object_set(to_json, "type", ast_json_string_create(type));
	res |= ast_json_object_set(to_json, "timestamp", ast_json_timeval(*tv, NULL));

	/* For global channel messages, the snapshot is optional */
	if (snapshot) {
		struct ast_json *json_channel;

		json_channel = ast_channel_snapshot_to_json(snapshot, sanitize);
		if (!json_channel) {
			ast_json_unref(to_json);
			return NULL;
		}

		res |= ast_json_object_set(to_json, "channel", json_channel);
	}

	if (res != 0) {
		ast_json_unref(to_json);
		return NULL;
	}

	return to_json;
}

static struct ast_json *tdd_start_to_json(
	struct stasis_message *message,
	const struct stasis_message_sanitizer *sanitize)
{
	return channel_blob_to_json(message, "TddStart", sanitize);
}

STASIS_MESSAGE_TYPE_DEFN_LOCAL(tdd_start_type,
	.to_json = tdd_start_to_json,
);

static struct ast_json *tdd_rx_msg_to_json(
	struct stasis_message *message,
	const struct stasis_message_sanitizer *sanitize)
{
	return channel_blob_to_json(message, "TddRxMsg", sanitize);
}

STASIS_MESSAGE_TYPE_DEFN_LOCAL(tdd_rx_msg_type,
	.to_json = tdd_rx_msg_to_json,
);

static struct ast_json *tdd_stop_to_json(
	struct stasis_message *message,
	const struct stasis_message_sanitizer *sanitize)
{
	return channel_blob_to_json(message, "TddStop", sanitize);
}

STASIS_MESSAGE_TYPE_DEFN_LOCAL(tdd_stop_type,
	.to_json = tdd_stop_to_json,
);

/*! \brief keep track of modem and audiohook state
 */
struct tdd_info {
	struct ast_audiohook audiohook; /* access to the audio streams */
	char *name;                     /* associated channel name */
	v18_state_t v18_state;          /* spandsp V.18 modem state */
	int rx_status;                  /* rx state (carrier up/down) */
	ast_mutex_t v18_tx_lock;        /* thread safe tx */
	unsigned int bufsiz;            /* receive buffer size */
	char *correlation;              /* a correlation ID for RX messages*/

	/* debug stats */
	long carrier_trans;			/* how many carrier transitions */
	long chars_recv;			/* actual received chars */
	long chars_sent;			/* sent chars */

	char underscores:1;			/* send received space chars as underscores */
	char international:1;		/* use Int'l 50bps mode instead of US 45.45 */
	char mute_rx:1;				/* replace incoming frames with silence while carrier is detected */
	char wait_rx:1;				/* TddRx app should wait for hangup or TddStop */
	char transmitting:1;		/* Whether we're still transmitting TDD data in the buffer */
};

enum starttddrx_flags {
	MUXFLAG_BUFSIZE = (1 << 0),
	MUXFLAG_CORRELATION = (1 << 1),
	MUXFLAG_UNDERSCORES = (1 << 2),
	MUXFLAG_MUTE_RX = (1 << 3),
	MUXFLAG_RX_WAIT = (1 << 4),
	MUXFLAG_NON_US_TTY = (1 << 5), /* selects 50bps, also translate to ITA_2_STD figs */
};

enum starttddrx_args {
	OPT_ARG_BUFSIZE,
	OPT_ARG_CORRELATION,
	OPT_ARG_ARRAY_SIZE, /* Always the last element of the enum */
};

AST_APP_OPTIONS(starttddrx_opts, {
	AST_APP_OPTION_ARG('b', MUXFLAG_BUFSIZE, OPT_ARG_BUFSIZE),
	AST_APP_OPTION_ARG('c', MUXFLAG_CORRELATION, OPT_ARG_CORRELATION),
	AST_APP_OPTION('i', MUXFLAG_NON_US_TTY),
	AST_APP_OPTION('s', MUXFLAG_UNDERSCORES),
	AST_APP_OPTION('m', MUXFLAG_MUTE_RX),
	AST_APP_OPTION('w', MUXFLAG_RX_WAIT),
});


/*! \brief Send spandsp log messages to asterisk.
 * \param level the spandsp logging level
 * \param msg the log message
 *
 * \note This is a spandsp callback function
 */
#if SPANDSP_RELEASE_DATE >= 20120902
static void spandsp_log(void *user_data, int level, const char *msg)
#else
static void spandsp_log(int level, const char *msg)
#endif
{
	if (level == SPAN_LOG_ERROR) {
		ast_log(LOG_ERROR, "%s", msg);
	} else if (level == SPAN_LOG_WARNING) {
		ast_log(LOG_WARNING, "%s", msg);
	} else {
		ast_log(LOG_DEBUG, "%s", msg);
	}
}

#if SPANDSP_RELEASE_DATE < 20120902
/*! \brief Send spandsp log messages to asterisk.
 * \param level the spandsp logging level
 * \param msg the log message
 *
 * \note This is a spandsp callback function
 */
static void spandsp_error_log(const char *msg)
{
	spandsp_log(SPAN_LOG_ERROR, msg);
}
#endif

/*! \brief Hook spandsp logging to asterisk.
 *
 * \param state the spandsp logging state struct
 */
static void set_logging(logging_state_t *state)
{

#if SPANDSP_RELEASE_DATE >= 20120902
	span_log_set_message_handler(state, spandsp_log, NULL);
#else
	span_log_set_message_handler(state, spandsp_log);
	span_log_set_error_handler(state, spandsp_error_log);
#endif

	span_log_set_level(state, SPAN_LOG_SHOW_SEVERITY | SPAN_LOG_SHOW_PROTOCOL | SPAN_LOG_DEBUG_3);
}

/*! The baudot code to shift from alpha to digits and symbols */
#if !defined(BAUDOT_FIGURE_SHIFT)
#define BAUDOT_FIGURE_SHIFT     0x1B
#endif
/*! The baudot code to shift from digits and symbols to alpha */
#if !defined(BAUDOT_LETTER_SHIFT)
#define BAUDOT_LETTER_SHIFT     0x1F
#endif

/*
  modified from library to support US-TTY and ITA2 symbol set differences
*/

static uint8_t tdd_v18_decode_baudot(v18_state_t *s, uint8_t ch, uint8_t intl)
{
    static const uint8_t conv[3][32] =
    {
        {"\bE\nA SIU\rDRJNFCKTZLWHYPQOBG^MXV^" },
        {"\b3\n- \a87\r$4',!:(5\")2#6019?+^./;^"}, /* updated to US-TTY, + instead of & */
        {"\b3\n- '87\r-4\a,!:(5+)2#6019?&^./=^" }  /* modified from US-TTY above to ITA-2 */
    };

    switch (ch) {
    case BAUDOT_FIGURE_SHIFT:
        s->baudot_rx_shift = 1 + intl;
        break;
    case BAUDOT_LETTER_SHIFT:
        s->baudot_rx_shift = 0;
        break;
    default:
        return conv[s->baudot_rx_shift][ch];
    }
    /* Return 0xFF if we did not produce a character */
    return 0xFF;
}

/*! \brief Callback for spandsp FSK bytes from the V.18 receiver
 *
 * \param user_data pointer to user data
 * \param byte the received byte, or a control byte (carrier)
 *
 * \note This is a spandsp callback function
 * \note This is an override of the V.18 built-in
 */
static void my_v18_tdd_put_async_byte(void *user_data, int byte)
{
	struct tdd_info *ti = user_data;
	v18_state_t *s = &ti->v18_state;
	uint8_t octet;

	if (byte < 0) {
		/* Special conditions */
		span_log(&s->logging, SPAN_LOG_FLOW, "V.18 signal status is %s (%d)\n", signal_status_to_str(byte), byte);
		switch (byte) {
		case SIG_STATUS_CARRIER_UP:
			s->consecutive_ones = 0;
			s->bit_pos = 0;
			s->in_progress = 0;
			s->rx_msg_len = 0;
			break;
		case SIG_STATUS_CARRIER_DOWN:
			span_log(&s->logging, SPAN_LOG_FLOW, "V.18 message buffer: %d\n", s->rx_msg_len);
			if (s->rx_msg_len > 0) {
				/* Whatever we have to date constitutes the message */
				s->rx_msg[s->rx_msg_len] = '\0';
				span_log(&s->logging, SPAN_LOG_FLOW, "[status] calling put_msg with %d chars", s->rx_msg_len);
				s->put_msg(s->user_data, s->rx_msg, s->rx_msg_len);
				s->rx_msg_len = 0;
			}
			break;
		default:
			span_log(&s->logging, SPAN_LOG_WARNING, "Unexpected special put byte value - %d!\n", byte);
			break;
		}
		return;
	}

	span_log(&s->logging, SPAN_LOG_FLOW, "Rx byte %x; rs_msg_len=%d\n", byte, s->rx_msg_len);

	if ((octet = tdd_v18_decode_baudot(s, byte, ti->international))) {
		span_log(&s->logging, SPAN_LOG_FLOW, "baudot returned 0x%x (%c)", octet, octet);
		if (octet == 0xff) {
			span_log(&s->logging, SPAN_LOG_FLOW, "filtering FF (0xff)"); /* FIG/LTR SHIFT */
		} else {
			s->rx_msg[s->rx_msg_len++] = octet;
		}
	} else {
		span_log(&s->logging, SPAN_LOG_FLOW, "baudot returned zero");
	}

	if (s->rx_msg_len >= ti->bufsiz) {
		s->rx_msg[s->rx_msg_len] = '\0';
		span_log(&s->logging, SPAN_LOG_FLOW, "[bufsiz] calling put_msg with %d chars", s->rx_msg_len);
		s->put_msg(s->user_data, s->rx_msg, s->rx_msg_len);
		s->rx_msg_len = 0;
	}
}

/*! \brief datastore destructor
 *
 * Called when a channel is destroyed to clean up the datastore. Also cleans up the audiohook.
 */
static void destroy_callback(void *data)
{
	struct tdd_info *ti = data;
	struct ast_channel *chan;

	RAII_VAR(struct stasis_message *, stasis_message, NULL, ao2_cleanup);
	RAII_VAR(struct ast_json *, stasis_message_blob, NULL, ast_json_unref);

	ast_debug(1, "TddRx datastore destroy callback\n");

	/*
	 * TODO: this is too late in channel lifecycle to send TddStop events as the channel
	 * is already gone.  Need to figure out how to hook channel destruction sooner in the
	 * destroy phase.
	 *
	 * Left here to support a StopTddRx command in the future.
	 */
	chan = ast_channel_get_by_name(ti->name);
	if (chan) {
		if (ast_strlen_zero(ti->correlation)) {
			ast_manager_event(chan, EVENT_FLAG_CALL, "TddStop", "Channel: %s\r\n", ti->name);

			stasis_message_blob = ast_json_pack("{s: s}", "tddstatus", "inactive");
		} else {
			ast_manager_event(chan, EVENT_FLAG_CALL, "TddStop", "Channel: %s\r\nCorrelation: %s\r\n", ti->name, ti->correlation);

			stasis_message_blob = ast_json_pack("{s: s, s: s}", "tddstatus", "inactive", "correlation", ti->correlation);
		}

		ast_channel_lock(chan);

		stasis_message = ast_channel_blob_create_from_cache(ast_channel_uniqueid(chan),
			tdd_stop_type(), stasis_message_blob);

		if (stasis_message) {
			stasis_publish(ast_channel_topic(chan), stasis_message);
		} else {
			ast_log(AST_LOG_WARNING, "TddRx not publishing TddStop stasis message for %s (null)\n", ti->name);
		}

		ast_channel_unlock(chan);
		ast_channel_unref(chan);
	}

	/* destroy the audiohook */
	ast_audiohook_lock(&ti->audiohook);
	ast_audiohook_detach(&ti->audiohook);
	ast_audiohook_unlock(&ti->audiohook);
	ast_audiohook_destroy(&ti->audiohook);

	/* free tdd_info */
	ast_mutex_destroy(&ti->v18_tx_lock);
	ast_free(ti->name);

	ast_debug(1, "TddRx modem { trans=%ld, sent=%ld, recv=%ld }\n", ti->carrier_trans, ti->chars_sent, ti->chars_recv);

	ast_free(ti);
}

/*! \brief datastore information
 */
static const struct ast_datastore_info tdd_datastore = {
	.type = "tdd",
	.destroy = destroy_callback
};

/*! \brief audiohook "manipulate" callback
 *
 * \note see ast_audiohook_manipulate_callback in audiohook.h
 */
static int hook_callback(struct ast_audiohook *audiohook, struct ast_channel *chan, struct ast_frame *frame, enum ast_audiohook_direction direction)
{
	struct ast_datastore *datastore = NULL;
	struct tdd_info *ti = NULL;
	struct ast_frame *cur = NULL; /* could get a list? */
	int ret = -1;                 /* indicate no manip was done */

	if (audiohook->status == AST_AUDIOHOOK_STATUS_DONE) {
		ast_debug(1, "TddRx audiohook status is DONE\n");
		return ret;
	}

	if (frame->frametype != AST_FRAME_VOICE) {
		char ft[40] = "unknown";
		char st[40] = "unknown";
		ast_frame_type2str(frame->frametype, ft, sizeof(ft));
		ast_frame_subclass2str(frame, st, sizeof(st), NULL, 0);
		ast_debug(1, "TddRx frametype not VOICE (%s/%s)\n", ft, st);
		return ret;
	}

	if (!(datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL))) {
		ast_log(AST_LOG_ERROR, "TddRx audiohook cb didn't find datastore\n");
		return ret;
	}

	ti = datastore->data;

	if (direction == AST_AUDIOHOOK_DIRECTION_READ) {
		/* pass audio samples from the hook to the modem */
		for (cur = frame; cur; cur = AST_LIST_NEXT(cur, frame_list)) {
			v18_rx(&ti->v18_state, cur->data.ptr, cur->samples);
			if (ti->mute_rx && ti->rx_status == SIG_STATUS_CARRIER_UP) {
				/* replace with silence so the callee doesn't have to hear tones */
				ast_frame_clear(cur);
				ret = 0;
			}
		}
	} else { /* AST_AUDIOHOOK_DIRECTION_WRITE */
		for (cur = frame; cur; cur = AST_LIST_NEXT(cur, frame_list)) {
			/* overwrite frame samples with modem samples, if any */
			ast_mutex_lock(&ti->v18_tx_lock);
			if (v18_tx(&ti->v18_state, cur->data.ptr, cur->samples) > 0) {
				ret = 0; /* changed at least one sample */
				ti->transmitting = 1;
			} else {
				ti->transmitting = 0;
			}
			ast_mutex_unlock(&ti->v18_tx_lock);
		}
	}

	return ret;
}

/*! \brief called by the V.18 modem when a TDD message has arrived
 *
 * \param user_data pointer to user supplied data
 * \param msg the TDD message (text) that was received
 *
 * \note This is a spandsp callback function
 */
static void tdd_put_msg(void *user_data, const uint8_t *msg, int len)
{
	struct tdd_info *ti = user_data;
	struct ast_channel *chan;
	char buf[513]; /* 2x modem buf +1 */
	size_t i, o;

	RAII_VAR(struct stasis_message *, stasis_message, NULL, ao2_cleanup);
	RAII_VAR(struct ast_json *, stasis_message_blob, NULL, ast_json_unref);

	ast_debug(1, "TddRx got a TDD message '%s' for channel %s\n", msg, ti->name);

	ti->chars_recv += len;

	chan = ast_channel_get_by_name(ti->name);
	if (!chan) {
		ast_log(AST_LOG_WARNING, "TddRx No channel matching '%s' found.\n", ti->name);
		return;
	}

	/* escape \r and \n for manager, optionally replace space with underscore */
	for (i = 0, o = 0; i < len; i++) {
		if (msg[i] == '\r') {
			buf[o++] = '\\';
			buf[o++] = 'r';
		} else if (msg[i] == '\n') {
			buf[o++] = '\\';
			buf[o++] = 'n';
		} else if (msg[i] == '\b') { /* null as backspace */
			buf[o++] = '\\';
			buf[o++] = 'b';
		} else if (msg[i] == '\a') { /* BEL */
			buf[o++] = '\\';
			buf[o++] = 'a';
		} else if (msg[i] == ' ' && ti->underscores == 1) {
			buf[o++] = '_';
		} else {
			buf[o++] = msg[i];
		}
	}
	buf[o] = '\0';

	if (ast_strlen_zero(ti->correlation)) {
		ast_manager_event(chan, EVENT_FLAG_CALL, "TddRxMsg",
			"Channel: %s\r\nMessage: %s\r\n", ti->name, buf);
		stasis_message_blob = ast_json_pack("{s: s}", "message", msg);
	} else {
		ast_manager_event(chan, EVENT_FLAG_CALL, "TddRxMsg",
			"Channel: %s\r\nMessage: %s\r\nCorrelation: %s\r\n",
			ti->name, buf, ti->correlation);
		stasis_message_blob = ast_json_pack("{s: s, s: s}", "message", msg, "correlation", ti->correlation);
	}

	ast_channel_lock(chan);

	stasis_message = ast_channel_blob_create_from_cache(ast_channel_uniqueid(chan),
		tdd_rx_msg_type(), stasis_message_blob);

	if (stasis_message) {
		stasis_publish(ast_channel_topic(chan), stasis_message);
	} else {
		ast_log(AST_LOG_WARNING, "TddRx not publishing stasis message for %s (null)\n", ti->name);
	}

	ast_channel_unlock(chan);
	ast_channel_unref(chan);
}

/*! \brief called by the FSK modem when the modem status changes
 *
 * \param user_data pointer to user supplied data
 * \param status the new receiver context status
 *
 * \note This is a spandsp callback function
 */
static void modem_rx_status(void *user_data, int status)
{
	struct tdd_info *ti = user_data;
	ti->rx_status = status;
	ti->carrier_trans++;

	/* forward status to the V.18 receiver we apparently stole the hook from */
	my_v18_tdd_put_async_byte(ti, status);
}

/*! \brief process TddRx app exec arguments
 *
 */
static void starttddrx_process_args(struct tdd_info *ti, const char *data)
{
	struct ast_flags flags = { 0 };
	char *parse;
	char *opts[OPT_ARG_ARRAY_SIZE] = { NULL, };

	unsigned int bufsiz = 256;
	char *correlation = NULL;
	char underscores = 0;
	char international = 0;
	char mute_rx = 0;
	char wait = 0;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(options);
		AST_APP_ARG(other);             /* Any remaining unused arguments */
	);

	parse = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, parse);

	if (args.options) {
		ast_app_parse_options(starttddrx_opts, &flags, opts, args.options);
		if (ast_test_flag(&flags, MUXFLAG_BUFSIZE)) {
			if (ast_strlen_zero(opts[OPT_ARG_BUFSIZE])) {
				ast_log(LOG_WARNING, "Ignoring buffer size option 'b': No value provided.\n");
			} else {
				if (sscanf(opts[OPT_ARG_BUFSIZE], "%u", &bufsiz) != 1 ) {
					ast_log(LOG_WARNING, "Ignoring buffer size option: could not parse numeric value.\n");
				} else {
					if (bufsiz < 1 || bufsiz > 256) {
						ast_log(LOG_WARNING, "Ignoring buffer size option: value out of range (1-256).\n");
						bufsiz = 256;
					}
				}
			}
		}
		if (ast_test_flag(&flags, MUXFLAG_CORRELATION)) {
			if (ast_strlen_zero(opts[OPT_ARG_CORRELATION])) {
				ast_log(LOG_WARNING, "Ignoring correlation option 'c': No value provided.\n");
			} else {
				correlation = opts[OPT_ARG_CORRELATION];
			}
		}
		if (ast_test_flag(&flags, MUXFLAG_NON_US_TTY)) {
			international = 1;
		}
		if (ast_test_flag(&flags, MUXFLAG_MUTE_RX)) {
			mute_rx = 1;
		}
		if (ast_test_flag(&flags, MUXFLAG_UNDERSCORES)) {
			underscores = 1;
		}
		if (ast_test_flag(&flags, MUXFLAG_RX_WAIT)) {
			wait = 1;
		}
	}

	ti->bufsiz = bufsiz; /* might be default, might be arg */

	if (!ast_strlen_zero(correlation)) {
		ti->correlation = ast_strdup(correlation);
	}
	
	ti->international = international;
	ti->mute_rx = mute_rx;
	ti->underscores = underscores;
	ti->wait_rx = wait;
}

/*! \brief Enable TDD processing on a channel
 *
 * \param chan the channel to add the audiohook on
 * \param data args passed to the application in the dialplan or via manager Options field
 *
 * adds the audiohook if there isn't one
 */
static int do_tdd_rx(struct ast_channel *chan, const char *data)
{
	struct ast_datastore *datastore = NULL;
	struct tdd_info *ti = NULL;

	v18_state_t *vs = NULL;
	fsk_rx_state_t *fs = NULL;

	RAII_VAR(struct stasis_message *, stasis_message, NULL, ao2_cleanup);
	RAII_VAR(struct ast_json *, stasis_message_blob, NULL, ast_json_unref);

	ast_debug(1, "TddRx exec\n");

	if (!chan) {
		return -1;
	}

	ast_channel_lock(chan);
	if ((datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL))) {
		ast_channel_unlock(chan);
		ast_debug(1, "TddRx TDD processing already enabled on %s\n", ast_channel_name(chan));
		return 1;
	}
	ast_channel_unlock(chan);

	ast_debug(1, "TddRx no datastore found, setting up\n");

	/* Allocate a new datastore to hold the reference to tdd info */
	if (!(datastore = ast_datastore_alloc(&tdd_datastore, NULL))) {
		ast_log(AST_LOG_ERROR, "TddRx failed to create datastore\n");
		return 2;
	}

	/* allocate the tdd info struct */
	if (!(ti = ast_calloc(1, sizeof(*ti)))) {
		ast_log(AST_LOG_ERROR, "TddRx failed to calloc tdd_info\n");
		ast_datastore_free(datastore);
		return 3;
	}

	starttddrx_process_args(ti, data);

	ti->rx_status = SIG_STATUS_CARRIER_DOWN; /* init status field with a sane value */

#if SPANDSP_RELEASE_DATE >= 20120902
	if (ti->international == 1) {
		v18_init(&ti->v18_state, 0, V18_MODE_5BIT_50, V18_AUTOMODING_NONE, tdd_put_msg, ti);
	} else {
		v18_init(&ti->v18_state, 0, V18_MODE_5BIT_4545, V18_AUTOMODING_NONE, tdd_put_msg, ti);
	}
#else
	if (ti->international == 1) {
		v18_init(&ti->v18_state, 0, V18_MODE_5BIT_50, tdd_put_msg, ti);
	} else {
		v18_init(&ti->v18_state, 0, V18_MODE_5BIT_45, tdd_put_msg, ti);
	}
#endif

	set_logging(v18_get_logging_state(&ti->v18_state));

	vs = &ti->v18_state;

#if SPANDSP_RELEASE_DATE >= 20120902
	fs = &vs->fsk_rx;
#else
	fs = &vs->fskrx;
#endif

	fsk_rx_set_modem_status_handler(fs, modem_rx_status, ti); /* override */
	fsk_rx_set_put_bit(fs, my_v18_tdd_put_async_byte, ti);    /* override */

	ast_audiohook_init(&ti->audiohook, AST_AUDIOHOOK_TYPE_MANIPULATE, "TDD", 0);
	ti->audiohook.manipulate_callback = hook_callback;

	ti->name = ast_strdup(ast_channel_name(chan));
	ast_mutex_init(&ti->v18_tx_lock);

	datastore->data = ti;

	ast_channel_lock(chan);
	ast_channel_datastore_add(chan, datastore);
	ast_channel_unlock(chan);
	ast_audiohook_attach(chan, &ti->audiohook);

	if (ast_strlen_zero(ti->correlation)) {
		ast_manager_event(chan, EVENT_FLAG_CALL, "TddStart", "Channel: %s\r\n", ti->name);

		stasis_message_blob = ast_json_pack("{s: s}", "tddstatus", "active");
	} else {
		ast_manager_event(chan, EVENT_FLAG_CALL, "TddStart", "Channel: %s\r\nCorrelation: %s\r\n", ti->name, ti->correlation);

		stasis_message_blob = ast_json_pack("{s: s, s: s}", "tddstatus", "active", "correlation", ti->correlation);
	}

	ast_channel_lock(chan);

	stasis_message = ast_channel_blob_create_from_cache(ast_channel_uniqueid(chan),
		tdd_start_type(), stasis_message_blob);

	if (stasis_message) {
		stasis_publish(ast_channel_topic(chan), stasis_message);
	} else {
		ast_log(AST_LOG_WARNING, "TddRx not publishing TddStart stasis message for %s (null)\n", ti->name);
	}
	ast_channel_unlock(chan);

	return 0;
}

/*! \brief Disable TDD processing on a channel
 *
 * \param chan the channel from which to remove the audiohook
 *
 * removes the audiohook if there is one
 */
static int do_tdd_stop(struct ast_channel *chan)
{
	struct ast_datastore *datastore = NULL;
	struct tdd_info *ti = NULL;

	if (!chan) {
		return -1;
	}

	ast_channel_lock(chan);
	datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL);
	if (!datastore) {
		ast_debug(1, "TddRx TDD processing not currently enabled on %s\n", ast_channel_name(chan));
		goto cleanup;
	}

	ti = datastore->data;
	if (ast_audiohook_remove(chan, &ti->audiohook)) {
		ast_log(LOG_WARNING, "Failed to remove TDD audiohook from channel %s\n", ast_channel_name(chan));
		goto cleanup;
	}

	if (ast_channel_datastore_remove(chan, datastore)) {
		ast_log(AST_LOG_WARNING, "Failed to remove TDD datastore from channel %s\n", ast_channel_name(chan));
		goto cleanup;
	}

	ast_datastore_free(datastore); /* triggers TddStop manager event */

cleanup:
	ast_channel_unlock(chan);
	return 0;
}

/*! \brief TddRx app exec
 *
 * \param chan the channel to add the audiohook on
 * \param data args passed to the application in the dialplan
 *
 * adds the audiohook if there isn't one, otherwise just return
 */
static int tdd_rx_exec(struct ast_channel *chan, const char *data)
{
	int res = 0;
	struct ast_datastore *datastore = NULL;
	struct tdd_info *ti = NULL;
	struct ast_silence_generator *g;

	if (!chan) {
		return -1;
	}

	res = do_tdd_rx(chan, data);

	if(res == 0) {
		ast_channel_lock(chan);
		if (!(datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL))) {
			/* should have just been created, so this really shouldn't be possible */
			ast_channel_unlock(chan);
			ast_log(LOG_WARNING, "Check WAIT_RX: Failed to find TDD datastore on channel %s\n", ast_channel_name(chan));
			return 0;
		}
		ast_channel_unlock(chan);

		ti = datastore->data;

		if(ti->wait_rx) {
			g = ast_channel_start_silence_generator(chan);
			for (;;) {
				ast_channel_lock(chan);
				datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL);
				ast_channel_unlock(chan);
				if (!datastore) {		/* TddStop removed datastore */
					res = 0;
					break;
				}
				if (ast_safe_sleep(chan, 250)) {	/* Channel hung up */
					res = -1;
					break;
				}
			}
			ast_channel_stop_silence_generator(chan, g);
			return res;
		}
	}

	return 0;
}

/*! \brief TddStop application (remove audiohook if one exists)
 *
 * \param chan the channel to add the audiohook on
 * \param data args passed to the application in the dialplan (currently not used)
 */
static int tdd_stop_exec(struct ast_channel *chan, const char *data)
{
	int result = do_tdd_stop(chan);

	switch (result) {
	case 0:
	case 1:
		return 0;
	default:
		return -1;
	}
}

static int tdd_wait_exec(struct ast_channel *chan, const char *data)
{
	struct ast_silence_generator *g;

	if (!chan) {
		return -1;
	}

	g = ast_channel_start_silence_generator(chan);
	for (;;) {
		struct ast_datastore *datastore = NULL;
		struct tdd_info *ti = NULL;
		ast_channel_lock(chan);
		datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL);
		if (!datastore) {
			ast_channel_unlock(chan);
			break; /* Either it's not currently transmitting, or the hook was removed while we were waiting. Either way, we're done */
		}
		ti = datastore->data;
		if (!ti->transmitting) {
			ast_debug(1, "TDD transmission has finished\n");
			ast_channel_unlock(chan);
			break;
		}
		ast_channel_unlock(chan);
		if (ast_safe_sleep(chan, 250)) { /* Channel hung up */
			ast_channel_stop_silence_generator(chan, g);
			return -1;
		}
	}
	ast_channel_stop_silence_generator(chan, g);
	return 0;
}

/*! \brief Manager command TddRx exec
 *
 */
static int manager_tddrx(struct mansession *s, const struct message *m)
{
	struct ast_channel *chan;
	int result;
	
	const char *name = astman_get_header(m, "Channel");
	const char *id = astman_get_header(m, "ActionID");
	const char *opts = astman_get_header(m, "Options");

	if (ast_strlen_zero(name)) {
		astman_send_error(s, m, "No channel specified");
		return AMI_SUCCESS;
	}

	chan = ast_channel_get_by_name(name);
	if (!chan) {
		astman_send_error(s, m, "No such channel");
		return AMI_SUCCESS;
	}

	result = do_tdd_rx(chan, opts);
	
	ast_channel_unref(chan);

	switch (result) {
	case 0:
		astman_append(s, "Response: Success\r\n");
		if (!ast_strlen_zero(id)) {
			astman_append(s, "ActionID: %s\r\n", id);
		}
		astman_append(s, "\r\n");
		return AMI_SUCCESS;

	case 1:
		astman_send_error(s, m, "TddRx TDD processing already enabled on this channel");
		return AMI_SUCCESS;

	case 2:
		astman_send_error(s, m, "TddRx failed to create datastore");
		return AMI_SUCCESS;
	
	case 3:
		astman_send_error(s, m, "TddRx failed to calloc tdd_info");
		return AMI_SUCCESS;

	default: /* not reached */
		astman_send_error(s, m, "Unspecified error enabling TDD on this channel");
		return AMI_SUCCESS;

	}
}

/*! \brief Manager command TddStop exec
 *
 */
static int manager_tddstop(struct mansession *s, const struct message *m)
{
	struct ast_channel *chan;
	int result;
	const char *name = astman_get_header(m, "Channel");
	const char *id = astman_get_header(m, "ActionID");

	if (ast_strlen_zero(name)) {
		astman_send_error(s, m, "No channel specified");
		return AMI_SUCCESS;
	}

	chan = ast_channel_get_by_name(name);
	if (!chan) {
		astman_send_error(s, m, "No such channel");
		return AMI_SUCCESS;
	}

	result = do_tdd_stop(chan);
	ast_channel_unref(chan);

	switch (result) {
	case 0:
		astman_append(s, "Response: Success\r\n");
		if (!ast_strlen_zero(id)) {
			astman_append(s, "ActionID: %s\r\n", id);
		}
		astman_append(s, "\r\n");
		return AMI_SUCCESS;
	case 1:
		astman_send_error(s, m, "TddRx TDD processing not currently enabled on this channel");
		return AMI_SUCCESS;
	default: /* not reached */
		astman_send_error(s, m, "Unspecified error disabling TDD on this channel");
		return AMI_SUCCESS;
	}
}

/*! \brief adds a message to the V.18 modem tx queue
 *
 * this is a common send method used by the manager "TddTx" and cli "tdd send" commands
 *
 * \param tdd_info the tdd data struct from the channel datastore
 * \param message the string of chars to send to the remote
 */
static void tdd_send_message(struct tdd_info *ti, const char *message)
{
	char buf[256];
	size_t msglen;
	int i, o;

	msglen = strlen(message);
	if (msglen > sizeof(buf) - 1) {
		ast_log(AST_LOG_WARNING, "TddTx: length exceeds %lu, message will be truncated.", sizeof(buf) - 1);
	}

	/* decode escapes */
	for (i = 0, o = 0; i < 256; i++) {
		if (i < (msglen -1) && message[i] == '\\') {
			switch (message[i + 1]) {
			case 'b': /* NUL */
				i++;
				buf[o++] = '\b';
				break;
			case 'a': /* BEL */
				i++;
				buf[o++] = '\a';
				break;
			case 'r':
				i++;
				buf[o++] = '\r';
				break;
			case 'n':
				i++;
				buf[o++] = '\n';
				break;
			default:
				buf[o++] = message[i];
			}
		} else {
			buf[o++] = message[i];
		}
	}
	buf[o] = '\0';

	ast_mutex_lock(&ti->v18_tx_lock);
	v18_put(&ti->v18_state, buf, strlen(buf));
	ti->chars_sent += strlen(buf);
	ti->transmitting = 1; /* In case TddWait is called before the audiohook fires, we have stuff in the queue so it should wait */
	ast_mutex_unlock(&ti->v18_tx_lock);
}

/*! \brief TddTx app exec
 *
 * \param chan the channel send TDD message on
 * \param data args passed to the application in the dialplan (the message to send)
 *
 * returns if the datastore is not found
 */
static int tdd_tx_exec(struct ast_channel *chan, const char *data)
{
	struct ast_datastore *datastore = NULL;
	struct tdd_info *ti = NULL;

	ast_debug(1, "TddTx exec\n");

	if (!chan) {
		return -1;
	}

	if (ast_strlen_zero(data)) {
		ast_log(LOG_ERROR, "TddTx called with no message\n");
		return -1;
	}

	ast_channel_lock(chan);

	/*! \todo tx really only works when audiohook is getting write frames (like from a bridge) */
/*
	if (ast_channel_is_bridged(chan) == 0) {
		ast_channel_unlock(chan);
		ast_log(LOG_ERROR, "Channel is not bridged\n");
		return -1;
	}
*/
	if (!(datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL))) {
		ast_channel_unlock(chan);
		ast_log(LOG_ERROR, "TddTx TDD processing not enabled on %s\n", ast_channel_name(chan));
		return -1;
	}
	ast_channel_unlock(chan);

	ti = datastore->data;

	tdd_send_message(ti, data);

	return 0;
}

/*! \brief Manager command TddTx exec
 */
static int manager_tddtx(struct mansession *s, const struct message *m)
{
	struct ast_channel *c;
	struct ast_datastore *datastore = NULL;
	struct tdd_info *ti = NULL;
	const char *name = astman_get_header(m, "Channel");
	const char *id = astman_get_header(m, "ActionID");
	const char *message = astman_get_header(m, "Message");

	if (ast_strlen_zero(name)) {
		astman_send_error(s, m, "No channel specified");
		return AMI_SUCCESS;
	}

	if (ast_strlen_zero(message)) {
		astman_send_error(s, m, "Message is required");
		return AMI_SUCCESS;
	}

	c = ast_channel_get_by_name(name);
	if (!c) {
		astman_send_error(s, m, "No such channel");
		return AMI_SUCCESS;
	}

	ast_channel_lock(c);

	/*! \todo tx really only works when audiohook is getting write frames (like from a bridge) */
/*
	if (ast_channel_is_bridged(c) == 0) {
		ast_channel_unlock(c);
		ast_channel_unref(c);
		astman_send_error(s, m, "Channel is not bridged");
		return AMI_SUCCESS;
	}
*/
	if (!(datastore = ast_channel_datastore_find(c, &tdd_datastore, NULL))) {
		ast_channel_unlock(c);
		ast_channel_unref(c);
		astman_send_error(s, m, "TDD is not enabled on this channel");
		return AMI_SUCCESS;
	}

	ast_channel_unlock(c);
	ast_channel_unref(c);

	ti = datastore->data;

	tdd_send_message(ti, message);

	astman_append(s, "Response: Success\r\n");

	if (!ast_strlen_zero(id)) {
		astman_append(s, "ActionID: %s\r\n", id);
	}

	astman_append(s, "\r\n");

	return AMI_SUCCESS;
}

/*! \brief CLI Tdd exec
 */
static char *handle_cli_tdd(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	/* handle start, stop, send, list, status ?? */
	struct ast_channel *chan;
	struct ast_datastore *datastore = NULL;
	struct tdd_info *ti = NULL;

	/* autocomplete channel arg */

	switch (cmd) {
	case CLI_INIT:
		e->command = "tdd {show|send}";
		e->usage =
			"Usage: tdd show <chan_name>\n"
			"         Show the TDD info for a channel.\n"
			"       tdd send <chan_name> <message>\n"
			"         Send a message on this channel.\n";
		return NULL;
	case CLI_GENERATE:
		return ast_complete_channels(a->line, a->word, a->pos, a->n, 2);
	}

	if (a->argc < 3) {
		return CLI_SHOWUSAGE;
	}

	if (!strcasecmp(a->argv[1], "send")) {
		if (a->argc < 4) {
			ast_cli(a->fd, "Must provide a message for 'send'.\n");
			return CLI_SHOWUSAGE;
		}
		if (ast_strlen_zero(a->argv[3])) {
			ast_cli(a->fd, "Must provide a message for 'send'.\n");
			return CLI_SHOWUSAGE;
		}
	} else if (strcasecmp(a->argv[1], "show")) {
		ast_cli(a->fd, "Don't know command '%s'.\n", a->argv[1]);
		return CLI_SHOWUSAGE;
	}

	chan =  ast_channel_get_by_name(a->argv[2]);
	if (!chan) {
		ast_cli(a->fd, "No channel matching '%s' found.\n", a->argv[2]);
		return CLI_SUCCESS;
	}

	ast_channel_lock(chan);
	/*! \todo tx really only works when audiohook is getting write frames (like from a bridge) */
/*
	if (ast_channel_is_bridged(chan) == 0) {
		ast_channel_unlock(chan);
		ast_channel_unref(chan);
		ast_cli(a->fd, "Channel is not bridged");
		return CLI_SUCCESS;
	}
*/

	if (!(datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL))) {
		ast_channel_unlock(chan);
		ast_channel_unref(chan);
		ast_cli(a->fd, "TDD not enabled on '%s'.\n", a->argv[2]);
		return CLI_SUCCESS;
	}
	ast_channel_unlock(chan);
	ast_channel_unref(chan);

	ti = datastore->data;

	if (!strcasecmp(a->argv[1], "send")) {
		tdd_send_message(ti, a->argv[3]);
	} else { /* show */
		ast_cli(a->fd, "Statistics for %s\n\n", a->argv[2]);
		ast_cli(a->fd, "  Carrier transitions: %ld\n", ti->carrier_trans);
		ast_cli(a->fd, "           Chars sent: %ld\n", ti->chars_sent);
		ast_cli(a->fd, "       Chars received: %ld\n", ti->chars_recv);
	}

	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_tdd[] = {
	AST_CLI_DEFINE(handle_cli_tdd, "Execute a TDD command")
};

static const char *rxapp = "TddRx";
static const char *txapp = "TddTx";
static const char *waitapp = "TddWait";
static const char *stopapp = "TddStop";

static int unload_module(void) {
	int res;

	STASIS_MESSAGE_TYPE_CLEANUP(tdd_start_type);
	STASIS_MESSAGE_TYPE_CLEANUP(tdd_rx_msg_type);
	STASIS_MESSAGE_TYPE_CLEANUP(tdd_stop_type);
	ast_cli_unregister_multiple(cli_tdd, ARRAY_LEN(cli_tdd));
	res = ast_unregister_application(rxapp);
	res |= ast_unregister_application(txapp);
	res |= ast_unregister_application(waitapp);
	res |= ast_unregister_application(stopapp);
	res |= ast_manager_unregister(rxapp);
	res |= ast_manager_unregister(txapp);
	res |= ast_manager_unregister(stopapp);

	return res;
}

static int load_module(void) {
	int res;

	STASIS_MESSAGE_TYPE_INIT(tdd_start_type);
	STASIS_MESSAGE_TYPE_INIT(tdd_rx_msg_type);
	STASIS_MESSAGE_TYPE_INIT(tdd_stop_type);
	ast_cli_register_multiple(cli_tdd, ARRAY_LEN(cli_tdd));
	res = ast_register_application_xml(rxapp, tdd_rx_exec);
	res |= ast_register_application_xml(txapp, tdd_tx_exec);
	res |= ast_register_application_xml(waitapp, tdd_wait_exec);
	res |= ast_register_application_xml(stopapp, tdd_stop_exec);
	res |= ast_manager_register_xml(rxapp, EVENT_FLAG_SYSTEM | EVENT_FLAG_CALL, manager_tddrx);
	res |= ast_manager_register_xml(txapp, EVENT_FLAG_SYSTEM | EVENT_FLAG_CALL, manager_tddtx);
	res |= ast_manager_register_xml(stopapp, EVENT_FLAG_SYSTEM | EVENT_FLAG_CALL, manager_tddstop);

	return res;
}

AST_MODULE_INFO_STANDARD_EXTENDED(ASTERISK_GPL_KEY, "TDD receive application");


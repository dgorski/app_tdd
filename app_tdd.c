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
		<syntax />
		<description>
			<para>The TddRx application is used to begin listening for TDD tones from the channel.  If TDD tones are detected, the received message will be posted via manager/stasis events for this channel.</para>
			<para>This application will exit immediately after setting up an audiohook.</para>
		</description>
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
			<para>If TDD processing is not enabled via TddRx, will return an error.</para>
		</description>
		<see-also>
			<ref type="application">TddRx</ref>
			<ref type="manager">TddTx</ref>
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
				<note><para>NOTE: TDD uses BAUDOT code which limits the characters that can be sent. Invalid characters are silently ignored.</para></note>
			</parameter>
		</syntax>
		<description>
			<para>This action sends a message via TDD/TTY tones on the current channel.  If TDD processing is not enabled on the channel an error will be returned.</para>
		</description>
		<see-also>
			<ref type="link">https://en.wikipedia.org/wiki/Baudot_code#ITA_2_and_US-TTY</ref>
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
	v18_state_t v18_state;          /* V.18 (45.45/TDD) modem state */
	int rx_status;                  /* rx state (carrier up/down) */
	ast_mutex_t v18_tx_lock;        /* thread safe tx */

	/* debug stats */
	long carrier_trans;             /* how many carrier transitions */
	long chars_recv;                /* actual received chars */
	long chars_sent;                /* sent chars */
};

/*! \brief Send spandsp log messages to asterisk.
 * \param level the spandsp logging level
 * \param msg the log message
 *
 * \note This is a spandsp callback function
 */
static void spandsp_log(int level, const char *msg)
{
	if (level == SPAN_LOG_ERROR) {
		ast_log(LOG_ERROR, "%s", msg);
	} else if (level == SPAN_LOG_WARNING) {
		ast_log(LOG_WARNING, "%s", msg);
	} else {
		ast_log(LOG_DEBUG, "%s", msg);
	}
}

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

/*! \brief Hook spandsp logging to asterisk.
 *
 * \param state the spandsp logging state struct
 */
static void set_logging(logging_state_t *state)
{
	span_log_set_message_handler(state, spandsp_log);
	span_log_set_error_handler(state, spandsp_error_log);

	span_log_set_level(state, SPAN_LOG_SHOW_SEVERITY | SPAN_LOG_SHOW_PROTOCOL | SPAN_LOG_DEBUG_3);
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

	if (byte < 0)
	{
		/* Special conditions */
		span_log(&s->logging, SPAN_LOG_FLOW, "V.18 signal status is %s (%d)\n", signal_status_to_str(byte), byte);
		switch (byte)
		{
		case SIG_STATUS_CARRIER_UP:
			s->consecutive_ones = 0;
			s->bit_pos = 0;
			s->in_progress = 0;
			s->rx_msg_len = 0;
			break;
		case SIG_STATUS_CARRIER_DOWN:
			span_log(&s->logging, SPAN_LOG_FLOW, "V.18 message buffer: %d\n", s->rx_msg_len);
			if (s->rx_msg_len > 0)
			{
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
	if ((octet = v18_decode_baudot(s, byte))) {
		span_log(&s->logging, SPAN_LOG_FLOW, "baudot returned 0x%x (%c)", octet, octet);
		if (octet == 0x08) {
			span_log(&s->logging, SPAN_LOG_FLOW, "filtering null/del (0x08)");
		} else if (octet == 0x0d) {
			span_log(&s->logging, SPAN_LOG_FLOW, "filtering CR (0x0d)");
		} else {
			s->rx_msg[s->rx_msg_len++] = octet;
		}
	} else {
		span_log(&s->logging, SPAN_LOG_FLOW, "baudot returned zero");
	}

	if (s->rx_msg_len >= 256)
	{
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
	if(chan) {
		ast_manager_event(chan, EVENT_FLAG_CALL, "TddStop", "Channel: %s\r\n", ti->name);

		stasis_message_blob = ast_json_pack("{s: s}", "tddstatus", "inactive");

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

	return;
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

	if(direction == AST_AUDIOHOOK_DIRECTION_READ) {
		/* pass audio samples from the hook to the modem */
		for (cur = frame; cur; cur = AST_LIST_NEXT(cur, frame_list)) {
			v18_rx(&ti->v18_state, cur->data.ptr, cur->samples);
			if(ti->rx_status == SIG_STATUS_CARRIER_UP) {
				/* make silent so the callee doesn't hear tones, could/should be optional */
				ast_frame_clear(cur);
				ret = 0;
			}
		}
	} else { /* AST_AUDIOHOOK_DIRECTION_WRITE */
		for (cur = frame; cur; cur = AST_LIST_NEXT(cur, frame_list)) {
			/* overwrite frame samples with modem samples, if any */
			ast_mutex_lock(&ti->v18_tx_lock);
			if(v18_tx(&ti->v18_state, cur->data.ptr, cur->samples) > 0)
				ret = 0; /* changed at least one sample */
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
	if(!chan) {
		ast_log(AST_LOG_WARNING, "TddRx No channel matching '%s' found.\n", ti->name);
		return;
	}

	/* escape \n for manager */
	for(i=0, o=0; i < len; i++) {
		if(msg[i] == '\n') {
			buf[o++] = '\\';
			buf[o++] = 'n';
		} else {
			buf[o++] = msg[i];
		}
	}
	buf[o] = '\0';

	ast_manager_event(chan, EVENT_FLAG_CALL, "TddRxMsg",
		"Channel: %s\r\nMessage: %s\r\n", ti->name, buf);

	stasis_message_blob = ast_json_pack("{s: s}", "message", msg);

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

/*! \brief TddRx app exec
 *
 * \param chan the channel to add the audiohook on
 * \param data args passed to the application in the dialplan (currently not used)
 *
 * adds the audiohook if there isn't one, otherwise just return
 */
static int tdd_rx_exec(struct ast_channel *chan, const char *data)
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
		return 0;
	}
	ast_channel_unlock(chan);

	ast_debug(1, "TddRx no datastore found, setting up\n");

	/* Allocate a new datastore to hold the reference to tdd info */
	if (!(datastore = ast_datastore_alloc(&tdd_datastore, NULL))) {
		ast_log(AST_LOG_ERROR, "TddRx failed to create datastore\n");
		return -1;
	}

	/* allocate the tdd info struct */
	if (!(ti = ast_calloc(1, sizeof(*ti)))) {
		ast_log(AST_LOG_ERROR, "TddRx failed to calloc tdd_info\n");
		ast_datastore_free(datastore);
		return -1;
	}

	ti->rx_status = SIG_STATUS_CARRIER_DOWN; /* init status field with a sane value */

	v18_init(&ti->v18_state, 0, V18_MODE_5BIT_45, tdd_put_msg, ti);

	set_logging(v18_get_logging_state(&ti->v18_state));

	vs = &ti->v18_state;
	fs = &vs->fskrx;

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

	ast_manager_event(chan, EVENT_FLAG_CALL, "TddStart", "Channel: %s\r\n", ti->name);

	stasis_message_blob = ast_json_pack("{s: s}", "tddstatus", "active");

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
	int i, o;

	if(strlen(message) > 255) {
		ast_log(AST_LOG_WARNING, "TddTx: length exceeds 255, message will be truncated.");
	}

	/* decode escapes */
	for(i=0,o=0; i < 256; i++) {
		if(i < (strlen(message) -1) && message[i] == '\\') {
			switch(message[i + 1]) {
			case '0': /* NUL */
				i++;
				buf[o++] = '\0';
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

	/* TODO: tx really only works when audiohook is getting write frames (like from a bridge) */
/*
	if(ast_channel_is_bridged(chan) == 0) {
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

	/* TODO: tx really only works when audiohook is getting write frames (like from a bridge) */
/*
	if(ast_channel_is_bridged(c) == 0) {
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
		if(ast_strlen_zero(a->argv[3])) {
			ast_cli(a->fd, "Must provide a message for 'send'.\n");
			return CLI_SHOWUSAGE;
		}
	} else if (strcasecmp(a->argv[1], "show")) {
		ast_cli(a->fd, "Don't know command '%s'.\n", a->argv[1]);
		return CLI_SHOWUSAGE;
	}

	chan =  ast_channel_get_by_name(a->argv[2]);
	if(!chan) {
		ast_cli(a->fd, "No channel matching '%s' found.\n", a->argv[2]);
		return CLI_SUCCESS;
	}

	ast_channel_lock(chan);
	/* TODO: tx really only works when audiohook is getting write frames (like from a bridge) */
/*
	if(ast_channel_is_bridged(chan) == 0) {
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

static char *rxapp = "TddRx";
static char *txapp = "TddTx";

static int unload_module(void) {
	int res;

	STASIS_MESSAGE_TYPE_CLEANUP(tdd_start_type);
	STASIS_MESSAGE_TYPE_CLEANUP(tdd_rx_msg_type);
	STASIS_MESSAGE_TYPE_CLEANUP(tdd_stop_type);
	ast_cli_unregister_multiple(cli_tdd, ARRAY_LEN(cli_tdd));
	res = ast_unregister_application(rxapp);
	res = ast_unregister_application(txapp);
	res |= ast_manager_unregister("TddTx");

	return res;
}

static int load_module(void) {
	int res;

	STASIS_MESSAGE_TYPE_INIT(tdd_start_type);
	STASIS_MESSAGE_TYPE_INIT(tdd_rx_msg_type);
	STASIS_MESSAGE_TYPE_INIT(tdd_stop_type);
	ast_cli_register_multiple(cli_tdd, ARRAY_LEN(cli_tdd));
	res = ast_register_application_xml(rxapp, tdd_rx_exec);
	res = ast_register_application_xml(txapp, tdd_tx_exec);
	res |= ast_manager_register_xml("TddTx", EVENT_FLAG_SYSTEM | EVENT_FLAG_CALL, manager_tddtx);

	return res;
}

AST_MODULE_INFO_STANDARD_EXTENDED(ASTERISK_GPL_KEY, "TDD receive application");

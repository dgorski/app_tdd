/*! \file
 *
 * \brief TDD() - Technology independent in-line TDD support
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
			<para>The TddRx application is used to begin listening for TDD tones from the channel.  If TDD tones are
detected the received message will be posted via a manager/stasis event for this channel.</para>
			<para>This application will exit immediately after setting up its audiohook.</para>
			<note><para></para></note>
		</description>
		<see-also>
			<ref type="function">AUDIOHOOK_INHERIT</ref>
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
				<para>The message to be sent.  Note that TDD uses BAUDOT code which limits the available characters that can be sent. Invalid characters are silently ignored.</para>
			</parameter>
		</syntax>
		<description>
			<para>This action sends a message via TDD/TTY tones on the current channel.  If the channel is not currently processing TDD then an error will be returned.</para>
		</description>
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

 ***/

STASIS_MESSAGE_TYPE_DEFN_LOCAL(tdd_rx_msg_type);

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
	/*ast_log(LOG_VERBOSE, " ~~ %s", msg);*/
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
		s->rx_msg[s->rx_msg_len++] = octet;
		span_log(&s->logging, SPAN_LOG_FLOW, "baudot returned 0x%x (%c)", octet, octet);
	} else {
		span_log(&s->logging, SPAN_LOG_FLOW, "baudot returned zero");
	}

	if (s->rx_msg_len >= 32) /* was 256 */
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
	ast_log(AST_LOG_VERBOSE, "TddRx datastore destroy callback\n");

	/* destroy the audiohook */
	ast_audiohook_lock(&ti->audiohook);
	ast_audiohook_detach(&ti->audiohook);
	ast_audiohook_unlock(&ti->audiohook);
	ast_audiohook_destroy(&ti->audiohook);

	/* free tdd_info */
	ast_mutex_destroy(&ti->v18_tx_lock);
	ast_free(ti->name);

	ast_log(AST_LOG_VERBOSE, "TddRx modem { trans=%ld, sent=%ld, recv=%ld }\n", ti->carrier_trans, ti->chars_sent, ti->chars_recv);

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
int hook_callback(struct ast_audiohook *audiohook, struct ast_channel *chan, struct ast_frame *frame, enum ast_audiohook_direction direction);
int hook_callback(struct ast_audiohook *audiohook, struct ast_channel *chan, struct ast_frame *frame, enum ast_audiohook_direction direction)
{
	struct ast_datastore *datastore = NULL;
	struct tdd_info *ti = NULL;
	struct ast_frame *cur = NULL; /* could get a list? */
	int ret = -1;                 /* indicate no manip was done */

	if (audiohook->status == AST_AUDIOHOOK_STATUS_DONE) {
		ast_debug(1, "TddRx audiohook status is DONE\n");
		return ret;
	}

	if (!(datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL))) {
		ast_log(AST_LOG_ERROR, "TddRx audiohook cb didn't find datastore\n");
		return ret;
	}

	ti = datastore->data;
	
	if (frame->frametype != AST_FRAME_VOICE) {
		return ret;
	}

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
			/* blindly write over frame samples with modem samples, if any */
			if(v18_tx(&ti->v18_state, cur->data.ptr, cur->samples) > 0)
				ret = 0; /* changed at least one sample */
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
void tdd_put_msg(void *user_data, const uint8_t *msg, int len);
void tdd_put_msg(void *user_data, const uint8_t *msg, int len)
{
	struct tdd_info *ti = user_data;
	struct ast_channel *chan;

	RAII_VAR(struct stasis_message *, stasis_message, NULL, ao2_cleanup);
	RAII_VAR(struct ast_json *, stasis_message_blob, NULL, ast_json_unref);

	ast_log(AST_LOG_VERBOSE, "TddRx got a TDD message '%s' for channel %s\n", msg, ti->name);

	ti->chars_recv += len;

	chan = ast_channel_get_by_name(ti->name);
	if(!chan) {
		ast_log(AST_LOG_WARNING, "TddRx No channel matching '%s' found.\n", ti->name);
		return;
	}

	ast_manager_event(chan, EVENT_FLAG_CALL, "TddRxMsg",
		"Channel: %s\r\nMessage: %s\r\n", ast_channel_name(chan), msg);

	stasis_message_blob = ast_json_pack("{s: s}", "message", msg);

	stasis_message = ast_channel_blob_create_from_cache(ast_channel_uniqueid(chan),
		tdd_rx_msg_type(), stasis_message_blob);

	if (stasis_message) {
		stasis_publish(ast_channel_topic(chan), stasis_message);
	} else {
    ast_log(AST_LOG_WARNING, "TddRx not publishing stasis message for %s (null)\n", ti->name);
  }

	chan = ast_channel_unref(chan);
}

/*! \brief called by the FSK modem when the modem status changes
 *
 * \param user_data pointer to user supplied data
 * \param status the new receiver context status
 *
 * \note This is a spandsp callback function
 */
void modem_rx_status(void *user_data, int status);
void modem_rx_status(void *user_data, int status)
{
	struct tdd_info *ti = user_data;
	ti->rx_status = status;
	ti->carrier_trans++;
	
	/*ast_log(AST_LOG_VERBOSE, "TddRx RX state changed to %s\n", signal_status_to_str(status));*/

	/* forward status to the v18 receiver we apparently stole the hook from */
	my_v18_tdd_put_async_byte(ti, status); 
}

/*! \brief TddRxpp exec
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

	ast_debug(1, "TddRx exec\n");

	if (!chan) {
		return -1;
	}

	ast_channel_lock(chan);
	if ((datastore = ast_channel_datastore_find(chan, &tdd_datastore, NULL))) {
		ast_channel_unlock(chan); 
		ast_log(LOG_ERROR, "TddRx TDD processing already enabled on %s\n", ast_channel_name(chan));
		return -1;
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
	/* v18_state_t* v18_init(v18_state_t *s, int calling_party, int mode, put_msg_func_t put_msg, void *user_data); */
	v18_init(&ti->v18_state, 0, V18_MODE_5BIT_45, tdd_put_msg, ti);

	set_logging(v18_get_logging_state(&ti->v18_state));

	v18_state_t *vs = &ti->v18_state;
	fsk_rx_state_t *fs = &vs->fskrx;
	fsk_rx_set_modem_status_handler(fs, modem_rx_status, ti); /* override */
	fsk_rx_set_put_bit(fs, my_v18_tdd_put_async_byte, ti); /* override */

	ast_audiohook_init(&ti->audiohook, AST_AUDIOHOOK_TYPE_MANIPULATE, "TDD", 0);
	ti->audiohook.manipulate_callback = hook_callback;

	ti->name = ast_strdup(ast_channel_name(chan));
	ast_mutex_init(&ti->v18_tx_lock);

	datastore->data = ti;

	ast_channel_lock(chan);
	ast_channel_datastore_add(chan, datastore);
	ast_channel_unlock(chan);
	ast_audiohook_attach(chan, &ti->audiohook);

	return 0;
}

/*! \brief Manager command TddTx exec
 *
 */
static int manager_tddtx(struct mansession *s, const struct message *m)
{
	struct ast_channel *c;
	struct ast_datastore *datastore = NULL;
	struct tdd_info *ti = NULL;
	const char *name = astman_get_header(m, "Channel");
	const char *id = astman_get_header(m, "ActionID");
	const char *message = astman_get_header(m, "Message");
	/*const char *command = astman_get_header(m, "Command");*/

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

  /* tx really only works when audiohook is getting write frames (like from a bridge) */
/*
  if(ast_channel_is_bridged(chan) == 0) {
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

	ast_mutex_lock(&ti->v18_tx_lock);
	v18_put(&ti->v18_state, message, strlen(message));
	ast_mutex_unlock(&ti->v18_tx_lock);
	
	ti->chars_sent += strlen(message);

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

	/* struct ast_channel *ast_channel_get_by_name_prefix(const char *name, size_t name_len); */
	chan =  ast_channel_get_by_name(a->argv[2]);
	if(!chan) {
		ast_cli(a->fd, "No channel matching '%s' found.\n", a->argv[2]);
		return CLI_SUCCESS;
	}

	ast_channel_lock(chan);
  /* tx really only works when audiohook is getting write frames (like from a bridge) */
/*
  if(ast_channel_is_bridged(chan) == 0) {
		ast_channel_unlock(c);
		ast_channel_unref(c);
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
		ast_mutex_lock(&ti->v18_tx_lock);
		v18_put(&ti->v18_state, a->argv[3], strlen(a->argv[3]));
		ti->chars_sent += strlen(a->argv[3]);
		ast_mutex_unlock(&ti->v18_tx_lock);
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

static char *app = "TddRx";

static int unload_module(void) {
	int res;

	STASIS_MESSAGE_TYPE_CLEANUP(tdd_rx_msg_type);
	ast_cli_unregister_multiple(cli_tdd, ARRAY_LEN(cli_tdd));
	res = ast_unregister_application(app);
	res |= ast_manager_register_xml("TddTx", EVENT_FLAG_SYSTEM | EVENT_FLAG_CALL, manager_tddtx);

	return res;
}

static int load_module(void) {
	int res;

	STASIS_MESSAGE_TYPE_INIT(tdd_rx_msg_type);
	ast_cli_register_multiple(cli_tdd, ARRAY_LEN(cli_tdd));
	res = ast_register_application_xml(app, tdd_rx_exec);
	res |= ast_manager_register_xml("TddTx", EVENT_FLAG_SYSTEM | EVENT_FLAG_CALL, manager_tddtx);

	return res;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "TDD receive application");

################################################################################
###                                 Imports                                  ###
################################################################################
#Standard imports
import logging
import json
import queue
import time
import threading

#Third party imports
import requests

################################################################################
###                                Class Def                                 ###
################################################################################
class Telegram_Handler(logging.Handler):
	"""
	Logging handler that posts log messages to specified telegram channel via a 
	bot. Note that a bot can only send messages to the same channel 20 times a 
	minute so this will have a rate limiter. So use this logger sparingly, 
	meaning use it for warnings, error, maybe info, but probably not debug 
	messages. Also, since this will be rate limited the actual sending of logs 
	to telegram will be done in a separate thread so that the logging call is 
	not blocking. So the log messages will be queued up.
	"""
	############################################################################
	def __init__(self, channel_id=None, api_key=None, config_fname=None, 
				 error_cb=None, app_name=""):
		"""
		Creates a new Telegram_Handler and starts its logging thread as a 
		daemon thread. Can input credentials in 2 different ways: directly 
		using the channel_id and api_key parameters or indirectly by loading 
		them from a json file using the config_fname parameter. To use the 
		direct method leave config_fname as None. To use the indirect method 
		from a config file set the config_fname parameter to the path of the 
		json config file to load from. The top level json object must have the 
		keys "telegram_handler_channel_id" and "telegram_handler_api_key" 
		holding the credentials (default). Or you can supply the channel_id and 
		api_key parameters with strings of the keys to look for in the config 
		file instead. Raises a ValueError if argument is incorrect type. Raises 
		a KeyError if config file missing required key. Raises other type of 
		error if there is a problem reading config file

		:param channel_id: id of telegram channel, group, or user to send log 
			messages to / name of key to get channel id from in config file 
			(leaving as None uses "telegram_handler_channel_id")
		:type channel_id: int / str
		:param api_key: api key of bot to post from / name of key to get api 
			key from in config file (leaving as None uses 
			"telegram_handler_api_key")
		:type api_key: str
		:param config_fname: full path to config file to load credentials from. 
			Leaving as None assumes channel_id and api_key arguments are 
			credentials. Setting to file path trys to load credentials from 
			top level object in json file
		:type config_fname: str
		:param error_cb: callback function to call if we encounter an 
			unexpected error while sending the logs to telegram. Takes log 
			message (str), response status code (int), and response text (str)
		:type erro_cb: function
		:param app_name: name of application (useful for having multiple 
			application log to same telegram channel)
		:type app_name: str
		:return: new instance of a Telegram_Handler with its logging thread 
			running as a daemon
		:rtype: Telegram_Handler
		"""
		#Call parent constructor
		super().__init__()

		#Save error callback
		if error_cb is None:
			self.error_cb = self._error_cb_stub
		else:
			self.error_cb = error_cb

		#Save app name
		self.app_name = str(app_name)

		#Load credentials from config file if using that method
		if config_fname is not None:
			with open(config_fname, 'r') as fh:
				config_data = json.load(fh)
			if channel_id is not None:
				channel_id = config_data[channel_id]
			else:
				channel_id = config_data["telegram_handler_channel_id"]
			if api_key is not None:
				api_key = config_data[api_key]
			else:
				api_key = config_data["telegram_handler_api_key"]

		#Should now have channel_id and api_key holding their correct values 
		#either loaded from config file or input directly so save them
		self.channel_id = int(channel_id)
		self.api_key = str(api_key)

		#Create URL endpoint for posting to telegram
		self.url = "https://api.telegram.org/bot%s/sendMessage" % self.api_key

		#Create queue for log messages
		self.log_q = queue.Queue()

		#Start logging thread
		self.log_thread = threading.Thread(target=self._log_to_telegram_loop, 
										   daemon=True)
		self.log_thread.start()

	############################################################################
	def emit(self, record):
		log_entry = self.format(record)
		if self.app_name:
			self.log_q.put(self.app_name + "\n" + log_entry)
		else:
			self.log_q.put(log_entry)

	############################################################################
	def _log_to_telegram_loop(self):
		"""
		Pulls log messages from the queue and posts them to telegram 
		(throttling if necessary)
		"""
		#Run continuously
		while True:
			#Get log message
			log_entry = self.log_q.get()

			#Try to post to telegram
			payload = {
				"chat_id": self.channel_id,
				"text": log_entry
			}
			resp = requests.post(self.url, data=payload)

			#Check status code and see if we are sending logs too fast or log 
			#was received
			while resp.status_code != 200:
				try:
					if resp.status_code == 429:
						#Sending logs too fast so wait and try again
						time.sleep(resp.json()['parameters']['retry_after'])
						resp = requests.post(self.url, data=payload)
					else:
						#Unexpected status code
						self.error_cb(log_entry, resp.status_code, resp.text)
				except Exception as e:
					self.error_cb(log_entry, 0, str(e))
					time.sleep(60)

	############################################################################
	def _error_cb_stub(self, log_entry, status_code, resp_text):
		"""
		Error callback function that does nothing. Acts as placeholder if user 
		doesn't pass in their own callback function

		:param log_entry: log entry that encountered unexpected error when 
			trying to log to telegram
		:type log_entry: str
		:param status_code: HTTP status code from the post to telegram call, if 
			status code is 0 then it means an exception occurred
		:type status_code: int
		:param resp_text: text of the response from the post to telegram, if 
			status code is 0 then this contains the exception that occurred as 
			a string
		:type resp_text: str
		"""
		pass

################################################################################
###                                Test Code                                 ###
################################################################################
if __name__ == "__main__":
	#Get config file containing credentials
	import argparse
	desc = "Tests the Telegram_Handler logging handler"
	parser = argparse.ArgumentParser(desc)
	help_str = "Path to config file containing telegram credentials"
	parser.add_argument("config_fname", help=help_str)
	help_str = "Name of application thats logging to telegram"
	parser.add_argument("-a", "--app_name", help=help_str, default="")
	args = parser.parse_args()

	#Get logger
	logger = logging.getLogger(__name__)
	logger.setLevel(logging.DEBUG)

	#Create console handler so we can compare log messages on the console and 
	#telegram
	console_handler = logging.StreamHandler()
	console_handler.setLevel(logging.INFO)

	#Create our telegram handler
	def error_cb(log_entry, status_code, resp_text):
		print("Could not log '%s'! Got status code %d" % (log_entry, 
														  status_code))
		print(resp_text)
	telegram_handler = Telegram_Handler(config_fname=args.config_fname, 
										error_cb=error_cb, 
										app_name=args.app_name)
	telegram_handler.setLevel(logging.INFO)

	#Create formatter and add to handlers
	fmt_str = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
	log_formatter = logging.Formatter(fmt_str)
	console_handler.setFormatter(log_formatter)
	telegram_handler.setFormatter(log_formatter)

	#Add handlers to logger
	logger.addHandler(console_handler)
	logger.addHandler(telegram_handler)

	#Logging should now be all setup so lets try to overwhelm the logger and 
	#see if it throttles correctly
	time.sleep(1)
	for ii in range(30):
		logger.info(ii)
		break
	try:
		time.sleep(120)
	except KeyboardInterrupt as e:
		pass

################################################################################
###                               End of File                                ###
################################################################################
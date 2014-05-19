from cassie.argparselite import ArgumentParserLite
from cassie.templates import CassieXMPPBotModule

class Module(CassieXMPPBotModule):
	def init_bot(self, *args, **kwargs):
		CassieXMPPBotModule.init_bot(self, *args, **kwargs)
		# self.bot.command_handler_set_permission('example', 'user')

	def cmd_example(self, args, jid, is_muc):
		parser = ArgumentParserLite('example', 'an example module')
		if not len(args):
			return parser.format_help()
		results = parser.parse_args(args)
		if not results:
			return parser.get_last_error()
		return 'Hello World!'

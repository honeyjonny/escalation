import re, sys, os
import idc
import idaapi
import idautils
from idaapi import Choose2

#
# default colors
#

BLUE = 0xffa52c
ORG = 0x2ca5ff
GREEN = 0x00ff7f

class Kernel(object):

	"""Kernel class for sunrace plugin"""

	def __init__(self):
		pass
		
	def analyze_callgr_profile(self, profile):
		"""
		Alalyze callgrind logs and for each func extract:
			- EA
			- trace addr set

		Return { Func_ea : trace_addrs_list, ... }
		"""
		fs = []

		for x in profile[4:]:
			fs += re.findall('fn=.[\w]*.*\n(0x[\w]*)....([\W\w]*)', x)

		nfs = []

		for f in fs:
			nfs.append(list(f))

		for i in nfs:
			insd = []
			for a in i[1].split('\n'):
				if a != '':
					cnd = a.split(' ')[0]
					if ('+' in cnd) or ('-' in cnd) or ('*' in cnd) or ('0x' in cnd):
						insd.append(cnd)
					elif ('jcnd' in cnd) or ('jmp' in cnd):
						pass
					# insd.append(a.split(' ')[0])
			i[1] = insd

		fs = {}

		for func in nfs:
			eip = int(func[0],16)
			trc = []
			# trc.append(eip)
			for instr in func[1]:
				if '+' in instr:
					eip = eval(str(eip)+instr)
					trc.append(eip)
				elif '*' in instr:
					trc.append(eip)
				elif '-' in instr:
					eip = eval(str(eip)+instr)
					trc.append(eip)
				elif '0x' in instr:
					eip = int(instr, 16)
					trc.append(eip)
			fs[int(func[0],16)] = trc

		del nfs
		return fs

	def clear_colors(self):
		ea = idc.ScreenEA()

		for function_ea in idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea)):
			for ins in idautils.FuncItems(function_ea):
				idc.SetColor(ins,idc.CIC_ITEM,0xFFFFFFFF)

	def color_single_profile(self, binprof, color=GREEN):
		"""
		Color single profile in IDA
			# default green - trace actually executed
		"""

		ea = idc.ScreenEA()

		actfuncs = []

		for rfunc in idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea)):
			if rfunc in binprof.keys():
				actfuncs.append(rfunc)
				for instr in binprof[rfunc]:
					idc.SetColor(instr, idc.CIC_ITEM, color)

		return actfuncs

	def color_profs(self, firstprof, secondprof, first_color=BLUE, second_color=ORG, common_color=GREEN):
		"""
		Color profiles in IDA, default: 
			# green - common
			# orange - second
			# blue - first
		"""

		ea = idc.ScreenEA()

		firstfuncs = []
		secondfuncs = []
		commfuncs = []

		# green - common
		# orange - second
		# blue - first

		for rfunc in idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea)):

			if (rfunc in firstprof.keys()) and (rfunc in secondprof.keys()):
				writed = []

				commfuncs.append(rfunc)

				for instr in firstprof[rfunc]:
					if instr in secondprof[rfunc]:
						idc.SetColor(instr, idc.CIC_ITEM, common_color)
						writed.append(instr)
					elif instr not in secondprof[rfunc]:
						idc.SetColor(instr, idc.CIC_ITEM, first_color)
						writed.append(instr)

				for instr in secondprof[rfunc]:
					if (instr in firstprof[rfunc]) and (instr not in writed):
						idc.SetColor(instr, idc.CIC_ITEM, common_color)
						writed.append(instr)
					elif (instr not in firstprof[rfunc]) and (instr not in writed):
						idc.SetColor(instr, idc.CIC_ITEM, second_color)
						writed.append(instr)
											
				del writed

			elif (rfunc in firstprof.keys()) and (rfunc not in secondprof.keys()):

				firstfuncs.append(rfunc)

				for instr in firstprof[rfunc]:
					idc.SetColor(instr, idc.CIC_ITEM, first_color)

			elif (rfunc in secondprof.keys()) and (rfunc not in firstprof.keys()):

				secondfuncs.append(rfunc)

				for instr in secondprof[rfunc]:
					idc.SetColor(instr, idc.CIC_ITEM, second_color)

		return {'first': firstfuncs, 'second': secondfuncs, 'comm': commfuncs }


	def make_funcs_from_profiles(self, firstprof, secondprof):
		"""
		Creates funcs in IDA, base on callgrind func EAs
		from two callgrind profiles
		"""

		count = 0
		funcs = []

		for i in firstprof.keys():
			if i in secondprof.keys():
				funcs.append(i)

		for j in secondprof.keys():
			if (j in firstprof.keys()) and (j not in funcs):
				funcs.append(j)

		for fun in funcs:
			ea = int(fun)
			if idc.MakeFunction(ea,idc.FindFuncEnd(ea)):
				count += 1

		del funcs
		return count

	def make_funcs_from_prof(self, binprof):
		"""
		Creates funcs in IDA, base on callgrind func EAs
		from one callgrind profile
		"""

		count = 0

		for i in binprof.keys():
			ea = int(i)
			if idc.MakeFunction(ea,idc.FindFuncEnd(ea)):
				count += 1
		return count

################################################################################################################

class FuncsColorChooser(Choose2):

	def __init__(self, title, func_chooser, first_prof_name, second_prof_name):
		Choose2.__init__(self, title, [ ["Address", 10 | Choose2.CHCOL_HEX], ["Name", 15 | Choose2.CHCOL_PLAIN] ])
		self.n = 0
		self.icon = 41
		self.first_flist = func_chooser['first']
		self.second_flist = func_chooser['second']
		self.comm_flist = func_chooser['comm']
		self.first_prof_name = first_prof_name
		self.second_prof_name = second_prof_name
		self.PopulateItems()

	def PopulateItems(self):
		self.items = [ [hex(x), idc.GetFunctionName(x), x] for x in self.first_flist + self.second_flist + self.comm_flist ]

	def OnClose(self):
		print "closed ", self.title

	def OnSelectLine(self, n):
		idc.Jump(self.items[n][2])

	def OnGetLine(self, n):
		return self.items[n]

	def OnGetSize(self):
		return len(self.items)

	def OnDeleteLine(self, n):
		idaapi.msg("Sorry, we don't support it.")
		return n

	def OnRefresh(self, n):
		self.PopulateItems()
		return n

	def show(self):
		t = self.Show()
		if t < 0:
			return False
		self.cmd_a = self.AddCommand("Count funcs this type")
		return True

	def OnCommand(self, n, cmd_id):
		if cmd_id == self.cmd_a:
			if self.items[n][2] in self.comm_flist:
				idc.Warning("Common Funcs: %d" % len(self.comm_flist))
			elif self.items[n][2] in self.first_flist:
				idc.Warning("First profile (blue) Funcs: %d\n\nProfile file: %s" % (len(self.first_flist), os.path.basename(self.first_prof_name)) )
			elif self.items[n][2] in self.second_flist:
				idc.Warning("Second Profile (orange) Funcs: %d\n\nProfile file: %s" % (len(self.second_flist), os.path.basename(self.second_prof_name)) )
		else:
			print "Unknown command:", cmd_id
		return 1

	def OnGetLineAttr(self, n):
		if self.items[n][2] in self.comm_flist:
			return [GREEN, 0]
		elif self.items[n][2] in self.first_flist:
			return [BLUE, 0]
		elif self.items[n][2] in self.second_flist:
			return [ORG, 0]

###############################################################################################################

class FuncsUniqueProfile(Choose2):

	def __init__(self, title, func_profile, color):
		Choose2.__init__(self, title, [ ["Address", 10 | Choose2.CHCOL_HEX], ["Name", 15 | Choose2.CHCOL_PLAIN] ])
		self.n = 0
		self.icon = 41
		self.functions = func_profile
		self.color = color
		self.PopulateItems()

	def PopulateItems(self):
		self.items = [ [hex(x), idc.GetFunctionName(x), x] for x in self.functions ]

	def OnClose(self):
		print "closed ", self.title

	def OnSelectLine(self, n):
		idc.Jump(self.items[n][2])

	def OnGetLine(self, n):
		return self.items[n]

	def OnGetSize(self):
		return len(self.items)

	def OnDeleteLine(self, n):
		idaapi.msg("Sorry, we don't support it.")
		return n

	def OnRefresh(self, n):
		self.PopulateItems()
		return n

	def OnGetLineAttr(self, n):
		return [self.color, 0]

	def show(self):
		t = self.Show()
		if t < 0:
			return False
		return True

###############################################################################################################

class SunracePlugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_KEEP
	comment = "Plugin combined DBI and Statical Analysis features"
	help = "Read code carefully"
	wanted_name = "Sunrace"
	wanted_hotkey = "Alt+F1"
	version = "v1.0"

	def init(self):
		idaapi.msg("Sunrace init [ . ]\n")
		self.menus = list()
		self.kern = Kernel()
		self.ColorFuncsView = None
		self.is_reanalyse = False
		self.is_singleprofile = False
		self.is_twoprofile = False
		self.singlname = ''
		self.fname = ''
		self.sname = ''
		return idaapi.PLUGIN_KEEP


	def run(self):
		idaapi.msg("Sunrace started [ * ]\n")
		self.AddMenus()

	def AddMenus(self):

		self.menus.append(idaapi.add_menu_item("Edit/Plugin/", "Sunrace: One prof make funcs", "Alt+F3", 0, self.OneProfMakeFuncs, ()))
		self.menus.append(idaapi.add_menu_item("Edit/Plugin/", "Sunrace: One prof color trace", "Alt+F1", 0, self.OneProfColor, ()))
		self.menus.append(idaapi.add_menu_item("Edit/Plugin/", "Sunrace: Two profs make funcs", "Alt+F4", 0, self.TwoProfMakeFuncs, ()))
		self.menus.append(idaapi.add_menu_item("Edit/Plugin/", "Sunrace: Two profs color trace", "Alt+F2", 0, self.TwoProfColor, ()))
		self.menus.append(idaapi.add_menu_item("Edit/Plugin/", "Sunrace: Get current funcs view", "Alt+1", 0, self.GetCurrentFuncsView, ()))
		self.menus.append(idaapi.add_menu_item("Edit/Plugin/", "Sunrace: Clear colors", "Alt+Q", 0, self.ClearColors, ()))
		self.menus.append(idaapi.add_menu_item("Edit/Plugin/", "Sunrace: REanalyse Colors, plz", "Alt+R", 0, self.REanalyseColors, ()))
		self.menus.append(idaapi.add_menu_item("Edit/Plugin/", "Sunrace: Exit", "Ctrl+Q", 0, self.term, ()))
		self.menus.append(idaapi.add_menu_item("Edit/Plugin/", "Sunrace: Quick Help", "Alt+Z", 0, self.QHelp,()))


	def term(self):
		for menu in self.menus:
			idaapi.del_menu_item(menu)
		idaapi.msg("Sunrace plugin unloaded... [ , ]\n")
		return True

	def QHelp(self):
		idc.Warning("""Sunrace Quick Help:\n\nExit: Ctrl+Q \nREanalyse Colors, plz: Alt+R \nClear colors: Alt+Q \nGet current funcs view: Alt+1 \nTwo profs color trace: Alt+F2 \nTwo profs make funcs: Alt+F4 \nOne prof color trace: Alt+F1 \nOne prof make funcs: Alt+F3 \n\nQuick Help: Alt+Z \n""")
		return True

	def ProgectWarning(self):
		idc.Warning("""Be careful!\n\nWhen you working with project:\n - FIRST selected file will BLUE colored\n - SECOND selected file will ORANGE\n\nKeep in mind, plz!!!""")
		return True

	def OneProfMakeFuncs(self):
		fname = idc.AskFile(0, '*.*', 'Select profile file, plz')
		prof = open(fname, 'rb')
		binprofile = prof.read().split('\n\n')

		binprof = self.kern.analyze_callgr_profile(binprofile)
		idaapi.msg("Tryind add funcs...\n")
		num = self.kern.make_funcs_from_prof(binprof)
		idc.Warning("%d funcs was added" % num)
		return True

	def TwoProfMakeFuncs(self):
		self.ProgectWarning()
		fname = idc.AskFile(0, '*.*', 'Select first profile file, plz')
		sname = idc.AskFile(0, '*.*', 'Select second profile file, plz')

		if (fname == None) or (sname == None):
			return False

		first = open(fname, 'rb')

		second = open(sname, 'rb')

		firstprofile = first.read().split('\n\n')

		secondprofile = second.read().split('\n\n')

		firstprof = self.kern.analyze_callgr_profile(firstprofile)

		secondprof = self.kern.analyze_callgr_profile(secondprofile)

		idaapi.msg("Tryind add funcs...\n")
		num = self.kern.make_funcs_from_profiles(firstprof, secondprof)
		idc.Warning("%d funcs was added" % num)
		return True

	def REanalyseColors(self):
		self.is_reanalyse = True
		if self.is_singleprofile:
			self.ClearColors()
			self.OneProfColor()
			self.is_reanalyse = False
			return True
		elif self.is_twoprofile:
			self.ClearColors()
			self.TwoProfColor()
			self.is_reanalyse = False
			return True
		elif (not self.is_singleprofile) and (not self.is_twoprofile):
			idc.Warning("Don't fool me!\nChoose profile file first.")
			self.is_reanalyse = False
			return False
		self.is_reanalyse = False
		return False

	def OneProfColor(self):
		self.is_singleprofile = True
		self.is_twoprofile = False

		if not self.is_reanalyse:
			self.singlname = idc.AskFile(0, '*.*', 'Select profile file, plz')

		if self.singlname == None:
			return False

		prof = open(self.singlname, 'rb')
		binprofile = prof.read().split('\n\n')

		idaapi.msg("Analysing profile...\n")
		binprof = self.kern.analyze_callgr_profile(binprofile)

		actfuncs = self.kern.color_single_profile(binprof, GREEN)

		if not self.is_reanalyse:

			YN = idc.AskYN(0, 'Do you want to make additional funcs, based on callgrind logs?\n(If func not already exist)')

			if YN == 1:
				idaapi.msg("Tryind add funcs...\n")
				num = self.kern.make_funcs_from_prof(binprof)
				idc.Warning("%d funcs was added" % num)

		self.ColorFuncsView = FuncsUniqueProfile("Actually funcs", actfuncs, GREEN)
		# self.ColorFuncsView.show()
		idaapi.msg("Done, enjoy work!")
		idaapi.msg("\nHelp:\n - Click Functions window and Type Alt+1 to see actually executed funcs from profile\n")
		self.is_reanalyse = False
		return True

	def TwoProfColor(self):
		self.is_singleprofile = False
		self.is_twoprofile = True

		if not self.is_reanalyse:
			self.ProgectWarning()
			self.fname = idc.AskFile(0, '*.*', 'Select first profile file, plz')
			self.sname = idc.AskFile(0, '*.*', 'Select second profile file, plz')

		if (self.fname == None) or (self.sname == None):
			return False

		first = open(self.fname, 'rb')

		second = open(self.sname, 'rb')

		firstprofile = first.read().split('\n\n')

		secondprofile = second.read().split('\n\n')

		idaapi.msg("Analysing profiles...\n")
		firstprof = self.kern.analyze_callgr_profile(firstprofile)

		secondprof = self.kern.analyze_callgr_profile(secondprofile)

		if not self.is_reanalyse:

			YN = idc.AskYN(0, 'Do you want to make additional funcs, based on callgrind logs?\n(If func not already exist)')

			if YN == 1:
				idaapi.msg("Tryind add funcs...\n")
				num = self.kern.make_funcs_from_profiles(firstprof, secondprof)
				idc.Warning("%d funcs was added" % num)

		actfuncs_dict = self.kern.color_profs(firstprof, secondprof, BLUE, ORG, GREEN)

		self.ColorFuncsView = FuncsColorChooser("Colored Funcs", actfuncs_dict, self.fname, self.sname)
		# self.ColorFuncsView.show()
		idaapi.msg("Done, enjoy work!\n")
		idaapi.msg("\nHelp:\n - Click Functions window and Type Alt+1 to see actually executed funcs from profiles\n")
		self.is_reanalyse = False
		return True

	def GetCurrentFuncsView(self):
		if self.ColorFuncsView == None:
			idc.Warning("First analyse profile file, man")
			return False
		else:
			self.ColorFuncsView.show()
			return True

	def ClearColors(self):
		idaapi.msg("Clear colors...\n")
		self.kern.clear_colors()
		return True

################################################################################################################w

if __name__ == '__main__':
	sp = SunracePlugin()
	sp.init()
	sp.run()
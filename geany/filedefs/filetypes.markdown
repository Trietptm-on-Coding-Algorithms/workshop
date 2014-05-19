# For complete documentation of this file, please see Geany's main documentation
[styling]
# foreground;background;bold;italic
default=0xffffff;0x2e3436;false;false
strong=0xffffff;0x2e3436;true;false
emphasis=0xffffff;0x2e3436;false;true
header1=0xad7fa8;0x2e3436;false;false
header2=0xad7fa8;0x2e3436;false;false
header3=0xad7fa8;0x2e3436;false;false
header4=0xad7fa8;0x2e3436;false;false
header5=0xad7fa8;0x2e3436;false;false
header6=0xad7fa8;0x2e3436;false;false
ulist_item=0x98bac5;0x2e3436;false;false
olist_item=0x98bac5;0x2e3436;false;false
blockquote=0xedd400;0x2e3436;false;false
strikeout=0xff7357;0x2e3436;false;false
hrule=0xff901e;0x2e3436;false;false
link=0x729fcf;0x2e3436;true;false
code=0x729fcf;0x2e3436;false;false
codebk=00x729fcf;0x2e3436;false;false

[settings]
# default extension used when saving files
# There's currently no consensus on what this is supposed to be: .text, .mdwn, .md, .mdt, .mkd, .markdown are all used. I'm going for the most obvious one
extension=markdown

[build_settings]
# %f will be replaced by the complete filename
# %e will be replaced by the filename without extension
# (use only one of it at one time)
compiler=markdown "%f" > "%e".html
run_cmd=

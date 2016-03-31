##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Template',
      'Description'    => %q{
        Template description.
      },
      'Author'        => 'Spencer McIntyre',
      'License'       => MSF_LICENSE,
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('STRING', [ false,  "String Description", 'default value' ]),
        OptInt.new('INTEGER',   [ false,  "Integer Description", 0 ]),
        OptBool.new('BOOL',     [ false,  "Boolean Description", true ]),
        OptEnum.new('ENUM',     [ false,  "Enum Description", 'VALUE1', ['VALUE1', 'VALUE2', 'VALUE3' ]])
      ], self.class)
    deregister_options()
    register_advanced_options(
      [
        OptString.new('ADVSTRING', [ false, "Advanced String Description", 'default value' ])
      ], self.class)
  end


  def run
    session
  end
end

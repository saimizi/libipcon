
subdir('mocklib')

enable_coverage = get_option('enable_coverage')

ut_link_args = ['-lcmocka']

if enable_coverage
  if meson.get_compiler('c').get_id() == 'gcc'
    add_project_arguments(['-fprofile-arcs', '-ftest-coverage'], language : 'c')
    ut_link_args += ['-lgcov', '--coverage']
  endif
endif

ut_sources = [
  'ut_main.c',
  'ut_ipcon_create_handler.c'
  ]

executable('ut_ipcon', 
  sources: ut_sources,
  link_with: [wrap_symbols_lib, libipcon],
  include_directories: ['../lib/', '../driver'],
  dependencies: libnl,
  link_args: ut_link_args,
  )



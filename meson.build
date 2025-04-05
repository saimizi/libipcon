project('libipcon', 'c', default_options : ['warning_level=3', 'optimization=2'])

unit_test = get_option('unit_test')
build_logger = get_option('build_logger')
build_sample = get_option('build_sample')
libnl = dependency('libnl-genl-3.0')


if unit_test
    add_project_arguments('-DUNIT_TEST', language : 'c')
    subdir('lib')
    subdir('test')
    if build_logger
        message('build_logger is ignored when unit_test is enabled')
    endif

    if build_sample
        message('build_sample is ignored when unit_test is enabled')
    endif
else
    subdir('lib')
    if build_logger
        subdir('logger')
    endif

    if build_sample
        subdir('samples')
    endif
endif

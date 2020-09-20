cat << END                                            >> $NGX_MAKEFILE

lua=$ngx_addon_dir/lua-5.4.0

$lua/src/liblua.a:
	cd $lua \\
	&& if [ -f src/liblua.a ]; then \$(MAKE) clean; fi \\
	&& \$(MAKE) linux

END

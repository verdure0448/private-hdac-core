package=cppzmq
$(package)_version=4.3.0
$(package)_download_path=https://github.com/zeromq/cppzmq/archive/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=27d1f56406ba94ee779e639203218820975cf68174f92fbeae0f645df0fcada4
$(package)_patches=


define $(package)_stage_cmds
	install -m 0644 -D $($(package)_extract_dir)/zmq.hpp $($(package)_staging_dir)/$(host_prefix)/include/zmq.hpp	
endef

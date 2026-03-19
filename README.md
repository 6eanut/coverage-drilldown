This script takes three arguments: the address of vmlinux, the address of rawcover, and the address of output.

python3 coverage_drilldown.py --vmlinux /home/jiakai/test-sysroot/linux/vmlinux --rawcover /home/jiakai/test-sysroot/riscvkaller/rawcover --output /home/jiakai/fuzzAndSelftests/drilldown/drilldown.html

The reason for this script is that syzkaller does provide coverage reports in html format, but I found it incomplete (for example, there are 10 kernel functions in the kernel source, and it only shows some of them, etc.).

This script was written by LLM and me. Feel free to raise issues if you have any questions.

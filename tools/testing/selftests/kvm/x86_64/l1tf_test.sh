MODULE=l1tf_test_mod

insmod ./test_modules/l1tf_test_kmod.ko
./l1tf_test  # The binary will spit out the KTAP directly.
rmmod "$MODULE"
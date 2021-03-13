#/bin/bash

file=$1

for framenumber in `tshark -r $file -Y "tcp.flags.syn==1 && !(tcp.flags.ack==1)" -T fields -e frame.number`
do
    frame=$framenumber
    echo $frame >> exclusion
    tempfile="tmp_`echo $frame`.pcapng"
    echo "Processing packet in frame $frame to $tempfile"
    tshark -r $file -w $tempfile -Y "frame.number==$frame"
    editcap -a 1:"New TCP SYN" $tempfile Commented_$tempfile
done
exclude=`cat exclusion`
editcap $file excluded_$file $exclude
mergecap -w Commented_$file Commented_tmp_*.pcapng excluded_$file

rm tmp_*.pcapng
rm Commented_tmp_*.pcapng
rm excluded _*.pcapng
rm exclusion
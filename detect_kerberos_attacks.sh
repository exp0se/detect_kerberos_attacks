#!/bin/bash
# tshark must be version 1.12+
if [ -z $1 ]; then
echo "No pcap file was provided"
echo "Usage: `basename $0` pcap_file mode"
echo "For mode, select:"
echo "key - to check for pass-the-key attacks"
echo "golden - to search for golden tickets or ptt attacks"
echo "silver - to search for silver tickets or ptt attacks"
echo "skeleton - to search for skeleton key"
echo "all - to search for all types of attacks"
exit 1
fi
function pass_the_key() {
# Detect pass-the-key attacks
# collect encryption types used
tshark -Y 'kerberos.msg_type == 10' -r $1 -T fields -e ip.src -e ip.dst -e kerberos.KerberosString -e kerberos.ENCTYPE 2>/dev/null > enctypes
pass_the_key_aes_256=`grep "18,0,0,0,0,0,0" enctypes`
if ! [[ -z $pass_the_key_aes_256 ]];then
echo "Detected AES-256 pass the key attack"
echo "times_key_was_used source_ip destination_ip user cipher"
echo "$pass_the_key_aes_256" | uniq -c
fi
pass_the_key_aes_128=`grep "17,0,0,0,0,0,0" enctypes`
if ! [[ -z $pass_the_key_aes_128 ]];then
echo "Detected AES-128 pass the key attack"
echo "times_key_was_used source_ip destination_ip user cipher"
echo "$pass_the_key_aes_128" | uniq -c
fi
pass_the_key_rc4=`grep "0,0,23,-133,-128,24,-135" enctypes`
if ! [[ -z $pass_the_key_rc4 ]];then
echo "Detected RC4 pass the key attack"
echo "times_key_was_used source_ip destination_ip user cipher"
echo "$pass_the_key_rc4" | uniq -c
fi
rm -f enctypes
}
function golden_ticket() {
# collect TGT tickets
tshark -Y 'kerberos.msg_type == 11' -r $1 -T fields -e ip.src -e ip.dst -e kerberos.KerberosString -e kerberos.cipher  -E separator=+ 2>/dev/null > tgt

# collect TGS tickets
tshark -Y 'kerberos.msg_type == 12' -r $1 -T fields -e ip.src -e ip.dst -e kerberos.KerberosString -e kerberos.cipher  -E separator=+ 2>/dev/null > tgs

# Detect forged TGTs
touch temp_tickets
tgs=`cut -d'+' -f4 tgs|cut -d',' -f1`
for ticket in $tgs
do
grep -q $ticket tgt
if [ $? -ne 0 ]; then
# skip already detected keys
grep -q $ticket temp_tickets
if [ $? -eq 0 ]; then
continue
fi
echo "Found forged TGT ticket. No initial AS-REQ and AS-REP was observed. "
echo "Detected stolen TGT ticket in pass-the-ticket or golden ticket attack."
echo "Incomplete packet capture can also cause this."
echo "Ticket information: "
echo "Source IP+Destination IP+Service used"
grep $ticket tgs|cut -d'+' -f1-3
echo $ticket >> temp_tickets
fi
done
rm -f tgt tgs temp_tickets
}
function silver_ticket() {
# collect granted TGS tickets
tshark -Y 'kerberos.msg_type == 13' -r $1 -T fields -e ip.src -e ip.dst -e kerberos.KerberosString -e kerberos.cipher  -E separator=+ 2>/dev/null > service_g

# collect used service tickets
tshark -Y '((kerberos.msg_type == 14) && !(kerberos.msg_type == 12))' -r $1 -T fields -e ip.src -e ip.dst -e kerberos.KerberosString -e kerberos.cipher  -E separator=+ 2>/dev/null > service_u

# Detect forged service tickets
touch temp_stickets
service_tickets=`cut -d'+' -f4 service_u|cut -d',' -f1`
for ticket in $service_tickets
do
grep -q $ticket service_g
if [ $? -ne 0 ]; then
# skip already detected keys
grep -q $ticket temp_stickets
if [ $? -eq 0 ]; then
continue
fi
echo "Found forged TGS ticket. No initial TGS-REQ and TGS-REP was observed. "
echo "Detected stolen service ticket in pass-the-ticket or silver ticket attack."
echo "Incomplete packet capture can also cause this."
echo "Ticket information: "
echo "Source IP+Destination IP+Service used"
grep $ticket service_u|cut -d'+' -f1-3
echo $ticket >> temp_stickets
fi
done
rm -f service_g service_u temp_stickets
}
function forged_pac() {
forged_pac=`tshark -Y 'kerberos.include_pac == false' -r $1 -T fields -e ip.src -e ip.dst -e kerberos.KerberosString 2>/dev/null` 
if ! [[ -z $forged_pac ]]; then
echo "Detected MS14-068 exploit."
echo "Forged PAC was created and used."
echo "Ticket information: "
echo "Source IP+Destination IP+Service used"
echo -e "$forged_pac\n"
fi
}
function skeleton_key() {
# collect supported enctypes per client 
tshark -Y '((kerberos.msg_type == 12) || (kerberos.msg_type == 10))' -r $1 -T fields -e ip.src -e kerberos.ENCTYPE 2>/dev/null| sort -u > client_enc
# collect chosen encryption by DC
tshark -Y '((kerberos.msg_type == 11) || (kerberos.msg_type == 13))' -r $1 -T fields -e ip.dst -e kerberos.etype 2>/dev/null| sort -u > chosen_enc
iplist=`awk '{ print $1 }' client_enc|sort -u`
for ip in $iplist
do 
cat client_enc| grep $ip|sort -u| awk '{ print $2 }'| egrep -q "(18|17)"
if [ $? -eq 0 ]; then
support_aes="true"
fi
cat chosen_enc| grep $ip|sort -u| awk '{ print $2 }'| egrep -q "(23|24|-135)"
if [ $? -eq 0 ]; then
chosen_rc4="true"
fi
if [[ $support_aes == "true" ]] && [[ $chosen_rc4 == "true" ]]; then
echo "Detected Skeleton Key!"
echo "Host is supporting AES, but was downgraded to RC4"
echo "Affected host: $ip"
fi
done
rm -f client_enc chosen_enc
}
if [[ $2 == "key" ]]; then
pass_the_key $1
elif [[ $2 == "golden" ]]; then
golden_ticket $1
elif [[ $2 == "silver" ]]; then
silver_ticket $1
elif [[ $2 == "forged_pac" ]]; then
forged_pac $1
elif [[ $2 == "skeleton" ]]; then
skeleton_key $1
elif [[ $2 == "all" ]]; then
pass_the_key $1
golden_ticket $1
silver_ticket $1
forged_pac $1
skeleton_key $1
else
echo "No mode was selected"
exit 1
fi

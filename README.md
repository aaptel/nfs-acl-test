Docs and ressources
-------------------

- "Permissions In Microsoft Services for UNIX v3.0"
   https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb463216(v=technet.10)
   Old but still good summary of how UNIX vs Windows permissions work

- "Use Setuid, Setgid, and Sticky Bits with Server for NFS"
   https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc731734(v%3dws.11)

- "How access AccessCheck works"
   https://docs.microsoft.com/en-us/windows/desktop/secauthz/how-dacls-control-access-to-an-object
   Explains how Windows ACL are checked

- "File Security and Access Rights"
  https://docs.microsoft.com/en-us/windows/desktop/fileio/file-security-and-access-rights

- "File and Folder permissions"
  https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb727008(v=technet.10)

- "SDC2010: Implementing NFS on the Windows Platform"
  http://people.redhat.com/steved/Bakeathon-2010/SDC2010-NFS-Windows.jbiseda.20100921.pdf

How to setup Windows NFS Server
-------------------------------

- https://virtualizationreview.com/articles/2017/06/29/how-to-set-up-an-nfs-server-on-windows-server-2012.aspx
- https://www.youtube.com/watch?v=PQIMg-Xc2es

How to dump Windows ACL
-----------------------

From windows (cmd or powershell):

    icacls <file>

Windows NFS Server in unmapped-user mode
----------------------------------------

The Windows NFS server will create NFS-specific SID for the unix user and
group. These are used as the file Owner and Group:

- Unix User  `SID: S-1-5-88-1-<uid>`
- Unix Group `SID: S-1-5-88-2-<gid>`
- Generic Unix "other" SID: `S-1-5-88-4`

For each file created by an NFS client:
- File owner set to Unix User SID
- File group set to Unix Group SID

Additionnaly, it sets the following ACL, in that order:
- Full (7777) mode bits ACE with the mode stored within the trustee SID
  - trustee = `S-1-5-88-3-<mode>`
  - ALLOW
  - access mask = 0 (N)
- User ACE
  - trustee = Unix User SID
  - ALLOW or ALLOW+DENY (so 1 or 2 ACE)
  - access mask = maps the owner mode bits
- Group ACE
  - trustee = Unix Group SID
  - ALLOW or ALLOW+DENY (so 1 or 2 ACE)
  - access mask = maps the group mode bits
- Other ACE
  - trustee = Unix Other SID
  - ALLOW or ALLOW+DENY (so 1 or 2 ACE)
  - access mask = maps the other mode bits

How to map the mode?
--------------------

Even when the unix mode is 0, users need to be able to do file
operations for Windows. As a result, Owner, Group and Other have
"base" rights which are always present regardless of the mode.

Owner: D,Rc,WDAC,WO,REA,WEA,RA,WA
- D: delete the file
- Rc,WDAC: read/write the file DACL
- WO: set file Owner
- REA,WEA,RA,WA: read/write attributes and extended attributes

Group & Other: Rc,S,REA,RA
- Rc: read the file DACL
- S: synchronize
- REA/RA: read attributes and extended attributes


    UNIX Windows
    r    RD,S
    w    WD,AD,DC
    x    X

Adding x
--------

For owner:
- -1- change  ALLOW +(X), -(N)

For group:
- -1- added   DENY  (S,X)
- -2- change  ALLOW +(X), -(N)

For other:
- -1- added   DENY  (S,X)
- -2- added   DENY  (S,X)
- -4- change  ALLOW +(X), -(N)

Adding w
--------

For owner:
- -1- change  ALLOW +(WD,AD,DC), -(N)

For group:
- -1- added   DENY  (S,WD,AD,DC)
- -2- change  ALLOW +(W,DC), -(S)

For other:
- -1- added   DENY  (S,WD,AD,DC)
- -2- added   DENY  (W,DC)
- -4- change  ALLOW +(W,DC), -(S)

Adding r
--------

For owner:
- -1- change  ALLOW +(RD), -(N)

For group:
- -1- added   DENY  (S,RD)
- -2- change  ALLOW +(RD), -(S)

For other:
- -1- added   DENY  (S,RD)
- -2- added   DENY  (S,RD)
- -4- change  ALLOW +(RD), -(S)


ACL algorithm
-------------

Pseudo-python code:

    is_access_allowed(ACL, user_sid, groups_sid, requested_access):
        if ACL is None:
            return True
        if len(ACL) == 0:
            return False
        for ACE in ACL:
            if ACE.trustee == user_sid or ACE.trustee in groups_sid:
            match = requested_access & ACE.access
            if ACE.type == ACCEPT and match != 0:
                requested_access &= ~match
            if requested_access == 0:
                return True
            elsif ACE.type == DENY and match != 0:
                return False

        return requested_access == 0

Mode mapping algorithm
----------------------

Not complete yet. Issues remaining with S flag...

    def unix_to_acl(uid, gid, mode):
        owner_sid = Sid('S-1-5-88-1-%d'%uid)
        group_sid = Sid('S-1-5-88-2-%d'%gid)
        other_sid = Sid('S-1-5-88-4')

        mode_sid = Sid('S-1-5-88-3-%d'%mode)
        mode_allow = 0

        owner_allow = perms_to_mask(['D','Rc','WDAC','WO','REA','WEA','RA','WA'])
        owner_deny = 0

        group_allow = perms_to_mask(['Rc','S','REA','RA'])
        group_deny = 0

        other_allow = perms_to_mask(['Rc','S','REA','RA'])
        other_deny = 0

        # r bit
        if mode & 0o0400:
            owner_allow |= perms_to_mask(['RD'])
            owner_allow |= perms_to_mask(['S']) # <==== wrong
        if mode & 0o0040:
            if not (mode&0o0400):
                owner_deny |= perms_to_mask(['S', 'RD'])
            group_allow |= perms_to_mask(['RD'])
            group_allow &= ~perms_to_mask(['S'])
        if mode & 0o0004:
            if not (mode&0o0400):
                owner_deny |= perms_to_mask(['S', 'RD'])
            if not (mode&0o0040):
                group_deny |= perms_to_mask(['RD'])
                group_deny |= perms_to_mask(['S']) # <===== wrong
            other_allow |= perms_to_mask(['RD'])
            other_allow &= ~perms_to_mask(['S'])

        # w bit
        if mode & 0o0200:
            owner_allow |= perms_to_mask(['WD','AD','DC'])
        if mode & 0o0020:
            if not (mode&0o0200):
                owner_deny |= perms_to_mask(['S', 'WD','AD','DC'])
            group_allow |= perms_to_mask(['W','DC'])
            group_allow &= ~perms_to_mask(['S'])
        if mode & 0o0002:
            if not (mode&0o0200):
                owner_deny |= perms_to_mask(['S', 'WD','AD','DC'])
            if not (mode&0o0020):
                group_deny |= perms_to_mask(['W', 'DC','AD','DC'])
            other_allow |= perms_to_mask(['W','DC'])
            other_allow &= ~perms_to_mask(['S'])

        # x bit
        if mode & 0o0100:
            owner_allow |= perms_to_mask(['X'])
        if mode & 0o0010:
            if not (mode&0o0100):
                owner_deny |= perms_to_mask(['S', 'X'])
            group_allow |= perms_to_mask(['X'])
        if mode & 0o0001:
            if not (mode&0o0100):
                owner_deny |= perms_to_mask(['S', 'X'])
            if not (mode&0o0010):
                group_deny |= perms_to_mask(['X'])
                group_deny |= perms_to_mask(['S']) # <==== wrong
            other_allow |= perms_to_mask(['X'])

        acl = []
        # mode
        acl.append(ACE(sid=mode_sid, deny=False, access=mode_allow))

        # owner
        acl.append(ACE(sid=owner_sid, deny=False, access=owner_allow))
        if owner_deny != 0:
            acl.append(ACE(sid=owner_sid, deny=True, access=owner_deny))
        # group
        acl.append(ACE(sid=group_sid, deny=False, access=group_allow))
        if group_deny != 0:
            acl.append(ACE(sid=group_sid, deny=True, access=group_deny))

        # other
        acl.append(ACE(sid=other_sid, deny=False, access=other_allow))
        if other_deny != 0:
            acl.append(ACE(sid=other_sid, deny=True, access=other_deny))

        return (owner_sid, group_sid, ACL(acelist=acl))


cifs.ko implementation notes
============================

noperms
dynperms
noacl
uid / forceuid
gid / forcegid


idsfromsid => CIFS_MOUNT_UID_FROM_ACL
cifsacl => CIFS_MOUNT_CIFS_ACL

READ PATH:

cifs_root_iget / cifs_mkdir_qinfo / cifs_revalidate_dentry_attr

cifs_get_inode_info
 if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_CIFS_ACL) {
   cifs_acl_to_fattr
    parse_sec_desc {
       sid_to_id
         if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_UID_FROM_ACL) {
           is_well_known_sid // UID
           is_well_known_sid // GID
     }
       parse_dacl
          is_well_known_sid  // MODE
    }
 }

WRITE PATH:

inode->setattr()
cifs_setattr
 cifs_setattr_nounix
  id_mode_to_cifs_acl
   build_sec_desc
    if (nmode != NO_CHANGE_64) { // chmod
      set_chmod_dacl
        fill_ace_for_sid

    }
    id_to_sid


TODO:

patch fill_ace_for_sid or set_chmod_dacl
but what to put in ACE?

type  = 1 (access denied, ok for 540 et 777, ..?)
flags = 0
size = ?
access_req = ?
88-3-<mode>

read https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb463216(v=technet.10)


---

    # create all file perms
    for s in $(seq 0 7); do
    for u in $(seq 0 7); do for g in $(seq 0 7); do for o in $(seq 0 7); do
        mode="$s$u$g$o"
        file="f$mode"
        touch $file && chown 1111:2222 $file && chmod $mode $file
        newmode="$(stat -c '%04a' "$file")"
        if [ "$newmode" = "$mode" ]; then
           echo "file $file mode $newmode OK"
        else
           echo "file $file mode $newmode ERR"
        fi
    done; done; done
    done


    for s in $(seq 0 7); do
    for u in $(seq 0 7); do for g in $(seq 0 7); do for o in $(seq 0 7); do
        mode="$s$u$g$o"
        file="f$mode"
        touch $file
        if ! chmod $mode $file ; then
           echo file $file mode $mode ERR CHMOD FAIL
           rm -f $file
           continue
        fi

        newmode="$(stat -c '%04a' "$file")"
        if [ "$newmode" = "$mode" ]; then
           echo "file $file mode $newmode OK"
        else
           echo "file $file mode $newmode ERR"
        fi
    done; done; done
    done

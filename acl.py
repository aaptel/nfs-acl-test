#!/usr/bin/env python3
import os
import sys
import re
import subprocess
import argparse
from pprint import pprint as P
from itertools import groupby

ARGS = None


def test_assumptions(modemap):
    #Test out some properties of the mapping
    # ACL is always in the form (and in that order)
    # S-1-5-88-3-<complete mode bits>:(N) <== always access mask zero, always ALLOW
    # S-1-5-88-1-<uid>:...        <== always ALLOW
    # S-1-5-88-1-<uid>:(DENY)...  <== this ACE is sometime omited
    # S-1-5-88-2-<gid>:...        <== always ALLOW
    # S-1-5-88-2-<gid>:(DENY)...  <== this ACE is sometime omited
    # S-1-5-88-4:...              <== always ALLOW

    for mode in range(0o7777+1):
        acl = modemap[mode]
        mode_ace = acl.get_nfs_type(3)

        if mode_ace.sid.subauth[-1] != mode:
            print("mode %04o doesn't match -3- ACE mode %04o"%(mode, mode_ace.sid.subauth[-1]))

        if acl.ace[0] != mode_ace:
            print("mode %04o doesn't start with -3- ACE"%mode)

        if mode_ace.deny or mode_ace.access != 0:
            print("mode %04o doesn't have expected ACE (deny:N => %s:%s)"%(
                ('deny' if mode_ace.deny else 'allow'), ','.join(mask_to_perms(mode_ace.access))
            ))

        expected_order = [3,1,2,4]
        ace_order = no_dups([x.sid.nfs_type() for x in acl.ace])
        if ace_order != expected_order:
            print("mode %04o has this ACE order: %s"%(mode, ace_order.__repr__()))
        else:
            for i in range(1, 4+1):
                g = [x for x in acl.ace if x.sid.nfs_type() == i]
                # check all types have 1 or 2 ACE, and type 3 has always exactly 1
                if i == 3:
                    assert len(g) == 1
                else:
                    assert 1 <= len(g) <= 2
                # check that if one rule => always accept, and 2 rules => 1 accept + 1 deny
                assert not g[0].deny
                if len(g) == 2:
                    assert g[1].deny

def diff_mode_bits(modemap):
    names = ["set-uid", "set-gid", "sticky",
             "u-read", "u-write", "u-xcute",
             "g-read", "g-write", "g-xcute",
             "o-read", "o-write", "o-xcute"]
    names.reverse()

    for bitpos in range(12):
        name = names[bitpos]
        bit = 1 << bitpos
        changeset_add = set()
        changeset_rem = set()

        for mode in range(0o7777+1):
            if mode & bit:
                newmode = mode&~bit
                chgs = changeset_rem
            else:
                newmode = mode|bit
                chgs = changeset_add

            r = cmp_mode(modemap, mode, newmode)
            r = '\n'.join(r)
            if r not in chgs:
                chgs.add(r)

        print("Adding bit %s (%d ways)\n========================="%(name, len(changeset_add)))
        for c in sorted(changeset_add, key=len):
            print(c)
            print()

        print("Removing bit %s (%d ways)\n========================"%(name, len(changeset_rem)))
        for c in sorted(changeset_rem, key=len):
            print(c)
            print()

    # cmp_mode(modemap, 0o0000, 0o0001)
    # cmp_mode(modemap, 0o0010, 0o0011)

def read_modes_list(f):
    buf = ''
    modemap = {}
    mode = -1
    for line in f.readlines():
        line = line.strip()
        if line == '':
            if 'S-1-' in buf and mode != -1:
                modemap[mode] = ACL(buf)
            buf = ''
        else:
            m = re.search('^f(\d+)', line)
            if m:
                mode = int(m.group(1), 8)
            buf += line+"\n"

    assert len(modemap)==0o7777+1
    return modemap

def side_diff_gen_acl(modemap, mode):
    uid = 1111
    gid = 2222
    diff = []
    if mode == 'all':
        for i in range(0o777+1):
            if not((i & 0o0004 and not(i&0o0040)) and not (i& 0o0001 and i&0o0010)):
                continue
            owner, group, acl = unix_to_acl(uid, gid, i)
            side_diff(modemap, i, i, modemap[i], acl)
            print("\n---------------------------------\n")
            if acl != modemap[i]:
                diff.append(i)
    else:
        mode = int(mode, 8)
        owner, group, acl = unix_to_acl(uid, gid, mode)
        side_diff(modemap, mode, mode, modemap[mode], acl)

def side_diff(modemap, modea, modeb, a=None, b=None):
    if a is None:
        a = modemap[modea]
    if b is None:
        b = modemap[modeb]

    bufA = ['=== mode %04o %s ==='%(modea, posix_mask_to_str(modea))]
    bufA.append(a.ace[0].__str__())

    bufB = ['=== mode %04o %s ==='%(modeb, posix_mask_to_str(modeb))]
    bufB.append(b.ace[0].__str__())

    nextA = 1
    nextB = 1

    def bufaddcmp(n1, n2):
        nonlocal nextA, nextB
        bufA.append(a.ace[nextA].__str__())
        bufB.append(b.ace[nextB].__str__())
        nextA += 1
        nextB += 1

        if nextA >= len(a.ace) and nextB >= len(b.ace):
            return
        elif nextA >= len(a.ace) and nextB < len(b.ace):
            bufA.append('')
            bufB.append(b.ace[nextB].__str__())
            return
        elif nextA < len(a.ace) and nextB >= len(b.ace):
            bufA.append(a.ace[nextA].__str__())
            bufB.append('')
            return

        at = a.ace[nextA].sid.nfs_type()
        bt = b.ace[nextB].sid.nfs_type()

        if at == n1 and bt == n1:
            bufA.append(a.ace[nextA].__str__())
            bufB.append(b.ace[nextB].__str__())
            nextA += 1
            nextB += 1
        elif at == n2 and bt == n1:
            bufA.append('')
            bufB.append(b.ace[nextB].__str__())
            nextB += 1
        elif at == n1 and bt == n2:
            bufA.append(a.ace[nextA].__str__())
            bufB.append('')
            nextA += 1
        elif at == n2 and bt == n2:
            pass

    bufaddcmp(1, 2)
    bufaddcmp(2, 4)
    bufaddcmp(4, 5)

    maxwidth = max([len(x) for x in bufA]) + 3
    for i in range(len(bufA)):
        fmt = '%%-%d.%ds' % (maxwidth, maxwidth)
        print((fmt % bufA[i])+bufB[i])

    print("\n===== DIFF =====")
    for s in cmp_mode(modemap, modea, modeb, a, b):
        print(s)

def main():
    ap = argparse.ArgumentParser(description="smb/nfs acl tool")
    ap.add_argument("-d", "--diff", help="diff 2 posix modes (MODE1:MODE2)")
    ap.add_argument("-g", "--gen-diff", help="diff generated acl and actual acl for MODE")
    ap.add_argument("-c", "--check", action="store_true", help="check various assumption")
    ap.add_argument("-D", "--diff-all", action="store_true", help="shows different ways to add/remove each bit")
    ap.add_argument("-m", "--multi-flag", action="store_true", default=False, help="use icacls 'multi-flag' rights when diffing access flags")
    ap.add_argument("file", help="icacls input file")
    global ARGS
    ARGS = ap.parse_args()

    modemap = read_modes_list(open(ARGS.file))
    if ARGS.check:
        test_assumptions(modemap)
    if ARGS.diff_all:
        diff_mode_bits(modemap)
    if ARGS.diff:
        modeA, modeB = [int(x, 8) for x in ARGS.diff.split(":")]
        side_diff(modemap, modeA, modeB)
    if ARGS.gen_diff:
        side_diff_gen_acl(modemap, ARGS.gen_diff)

def cmp_mode(modemap, modea, modeb, a=None, b=None):
    if a is None:
        a = modemap[modea]
    if b is None:
        b = modemap[modeb]
    a_ace_1 = [x for x in a.ace if x.sid.nfs_type() == 1]
    a_ace_2 = [x for x in a.ace if x.sid.nfs_type() == 2]
    a_ace_4 = [x for x in a.ace if x.sid.nfs_type() == 4]
    b_ace_1 = [x for x in b.ace if x.sid.nfs_type() == 1]
    b_ace_2 = [x for x in b.ace if x.sid.nfs_type() == 2]
    b_ace_4 = [x for x in b.ace if x.sid.nfs_type() == 4]

    def cmp_ace(old, new):
        oldp = old.access
        newp = new.access
        added = (newp & (~oldp))
        removed = (oldp & (~newp))
        return "+(%s), -(%s)"%(','.join(mask_to_perms(added, include_multi=ARGS.multi_flag)), ','.join(mask_to_perms(removed, include_multi=ARGS.multi_flag)))

    def cmp_ace_group(ag, bg, n):
        r = []
        if ag[0] != bg[0]:
            r.append("-%d- change ALLOW   %s"%(n,cmp_ace(ag[0], bg[0])))
        if len(ag) == 1 and len(bg) == 2:
            r.append("-%d- added   DENY  (%s)"%(n, ','.join(mask_to_perms(bg[1].access))))
        if len(ag) == 2 and len(bg) == 1:
            r.append("-%d- removed DENY  (%s)"%(n, ','.join(mask_to_perms(ag[1].access))))
        if len(ag) == 2 and len(bg) == 2:
            if ag[1] != bg[1]:
                r.append("-%d- change DENY    %s"%(n,cmp_ace(ag[1], bg[1])))
        return r


    #print("%04o => %04o\n----\n%s%s---"%(modea, modeb, wrap("A: ", str(a)), wrap("B: ", str(b))))
    r = []
    r.extend(cmp_ace_group(a_ace_1, b_ace_1, 1))
    r.extend(cmp_ace_group(a_ace_2, b_ace_2, 2))
    r.extend(cmp_ace_group(a_ace_4, b_ace_4, 4))
    #print("-----------------")
    return r

class Sid:
    def __init__(self, sidstr):
        parts = sidstr.split('-')[1:] # skip "S-"
        self.rev = int(parts[0])
        base = 16 if parts[1].startswith('0x') else 10
        self.auth = int(parts[1], base)
        self.subauth = [int(x) for x in parts[2:]]

    def nfs_type(self):
        if len(self.subauth) == 2:
            return self.subauth[-1]
        elif len(self.subauth) == 3:
            return self.subauth[-2]
        assert False

    def __str__(self):
        auth = ("0x%x" if self.auth >= 2**32 else "%d")%self.auth
        return  "S-%d-%s-%s"%(self.rev, auth, '-'.join(map(str, self.subauth)))

    def __eq__(self, other):
        return self.__str__() == other.__str__()

class ACE:
    def __init__(self, acestr=None, sid=None, deny=None, access=None):
        if acestr is not None:
            m = re.search(r'''(S-1-.+?):((?:\(DENY\))?)\((.+?)\)''', acestr)
            assert m
            self.sid = Sid(m.group(1))
            self.deny = (m.group(2) == '(DENY)')
            self.access = perms_to_mask(m.group(3).split(','))
            #assert ','.join(mask_to_perms(self.access)) == m.group(3)
        else:
            self.sid = Sid(sid.__str__())
            self.deny = deny
            self.access = access


    def __str__(self):
        return '%s:%s(%s)'%(
            self.sid.__str__(),
            '(DENY)' if self.deny else '',
            ','.join(mask_to_perms(self.access, include_multi=ARGS.multi_flag))
        )

    def __eq__(self, other):
        return self.__str__() == other.__str__()

class ACL:
    def __init__(self, aclstr=None, acelist=None):
        if acelist is not None:
            self.ace = acelist
        else:
            self.ace = []
            for line in aclstr.split('\n'):
                m = re.search('(S-1.+)', line)
                if m:
                    self.ace.append(ACE(m.group(1)))

    def get_nfs_type(self, stype):
        for ace in self.ace:
            if ace.sid.nfs_type() == stype:
                return ace

    def __str__(self):
        return ''.join([x.__str__()+"\n" for x in self.ace])

    def __eq__(self, other):
        if len(other.ace) == len(self.ace):
            for i in range(len(self.ace)):
                if self.ace[i] != other.ace[i]:
                    return False
            return True
        return False


def no_dups(L):
    return [x[0] for x in groupby(L)]

def wrap(pref, txt):
    if txt[-1] == '\n':
        txt = txt[:-1]
    return pref+txt.replace('\n', '\n'+pref)

# access masks are divided up like this:
#       0xabccdddd
#       where
#          a = generic rights bits        SEC_GENERIC_
#          b = flags                      SEC_FLAG_
#          c = standard rights bits       SEC_STD_
#          d = object type specific bits  SEC_{FILE,DIR,REG,xxx}_
#
# common combinations of bits are prefixed with SEC_RIGHTS_
SEC_MASK_GENERIC         = 0xF0000000
SEC_MASK_FLAGS           = 0x0F000000
SEC_MASK_STANDARD        = 0x00FF0000
SEC_MASK_SPECIFIC        = 0x0000FFFF

# generic bits
SEC_GENERIC_ALL          = 0x10000000
SEC_GENERIC_EXECUTE      = 0x20000000
SEC_GENERIC_WRITE        = 0x40000000
SEC_GENERIC_READ         = 0x80000000

# flag bits
SEC_FLAG_SYSTEM_SECURITY = 0x01000000
SEC_FLAG_MAXIMUM_ALLOWED = 0x02000000

# standard bits
SEC_STD_DELETE           = 0x00010000
SEC_STD_READ_CONTROL     = 0x00020000
SEC_STD_WRITE_DAC        = 0x00040000
SEC_STD_WRITE_OWNER      = 0x00080000
SEC_STD_SYNCHRONIZE      = 0x00100000

SEC_STD_REQUIRED         = 0x000F0000
SEC_STD_ALL              = 0x001F0000

# file specific bits
SEC_FILE_READ_DATA       = 0x00000001
SEC_FILE_WRITE_DATA      = 0x00000002
SEC_FILE_APPEND_DATA     = 0x00000004
SEC_FILE_READ_EA         = 0x00000008
SEC_FILE_WRITE_EA        = 0x00000010
SEC_FILE_EXECUTE         = 0x00000020
SEC_FILE_READ_ATTRIBUTE  = 0x00000080
SEC_FILE_WRITE_ATTRIBUTE = 0x00000100
SEC_FILE_ALL             = 0x000001ff

# directory specific bits
SEC_DIR_LIST             = 0x00000001
SEC_DIR_ADD_FILE         = 0x00000002
SEC_DIR_ADD_SUBDIR       = 0x00000004
SEC_DIR_READ_EA          = 0x00000008
SEC_DIR_WRITE_EA         = 0x00000010
SEC_DIR_TRAVERSE         = 0x00000020
SEC_DIR_DELETE_CHILD     = 0x00000040
SEC_DIR_READ_ATTRIBUTE   = 0x00000080
SEC_DIR_WRITE_ATTRIBUTE  = 0x00000100

# registry entry specific bits
SEC_REG_QUERY_VALUE      = 0x00000001
SEC_REG_SET_VALUE        = 0x00000002
SEC_REG_CREATE_SUBKEY    = 0x00000004
SEC_REG_ENUM_SUBKEYS     = 0x00000008
SEC_REG_NOTIFY           = 0x00000010
SEC_REG_CREATE_LINK      = 0x00000020

# ldap specific access bits
SEC_ADS_CREATE_CHILD     = 0x00000001
SEC_ADS_DELETE_CHILD     = 0x00000002
SEC_ADS_LIST             = 0x00000004
SEC_ADS_SELF_WRITE       = 0x00000008
SEC_ADS_READ_PROP        = 0x00000010
SEC_ADS_WRITE_PROP       = 0x00000020
SEC_ADS_DELETE_TREE      = 0x00000040
SEC_ADS_LIST_OBJECT      = 0x00000080
SEC_ADS_CONTROL_ACCESS   = 0x00000100
#--------------------------------------------
# These seems wrong, see below
SEC_RIGHTS_FILE_READ    = (SEC_STD_READ_CONTROL |
                           SEC_STD_SYNCHRONIZE |
      		           SEC_FILE_READ_DATA |
                           SEC_FILE_READ_ATTRIBUTE |
                           SEC_FILE_READ_EA)

SEC_RIGHTS_FILE_WRITE   = (SEC_STD_READ_CONTROL |
                           SEC_STD_SYNCHRONIZE |
      		           SEC_FILE_WRITE_DATA |
                           SEC_FILE_WRITE_ATTRIBUTE |
                           SEC_FILE_WRITE_EA |
                           SEC_FILE_APPEND_DATA)

SEC_RIGHTS_FILE_EXECUTE = (SEC_STD_SYNCHRONIZE |
	                   SEC_STD_READ_CONTROL |
	                   SEC_FILE_READ_ATTRIBUTE |
                           SEC_FILE_EXECUTE)

# probably wrong so we redefine here:
# from https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=netframework-4.7.2
SEC_RIGHTS_FILE_WRITE = 278
SEC_RIGHTS_FILE_READ = 131209
SEC_RIGHTS_FILE_EXECUTE = 32


#---------------------------------------------

# ACE flags
SEC_ACE_FLAG_OBJECT_INHERIT		= 0x01
SEC_ACE_FLAG_CONTAINER_INHERIT		= 0x02
SEC_ACE_FLAG_NO_PROPAGATE_INHERIT	= 0x04
SEC_ACE_FLAG_INHERIT_ONLY		= 0x08
SEC_ACE_FLAG_INHERITED_ACE		= 0x10
SEC_ACE_FLAG_VALID_INHERIT		= 0x0f
SEC_ACE_FLAG_SUCCESSFUL_ACCESS		= 0x40
SEC_ACE_FLAG_FAILED_ACCESS		= 0x80

# ACE type
SEC_ACE_TYPE_ACCESS_ALLOWED		= 0
SEC_ACE_TYPE_ACCESS_DENIED		= 1
SEC_ACE_TYPE_SYSTEM_AUDIT		= 2
SEC_ACE_TYPE_SYSTEM_ALARM		= 3
SEC_ACE_TYPE_ALLOWED_COMPOUND		= 4
SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT	= 5
SEC_ACE_TYPE_ACCESS_DENIED_OBJECT	= 6
SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT	= 7
SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT	= 8

#--------------------------------------------

# A sequence of simple rights:
#     F (full access)
#     M (modify access)
#     RX (read and execute access)
#     R (read-only access)
#     W (write-only access)
#
# A comma-separated list in parenthesis of specific rights:
#     D (delete)
#     RC (read control)
#     WDAC (write DAC)
#     WO (write owner)
#     S (synchronize) SEC_STD_SYNCHRONIZE
#     AS (access system security)
#     MA (maximum allowed)
#     GR (generic read)
#     GW (generic write)
#     GE (generic execute)
#     GA (generic all)
#     RD (read data/list directory)
#     WD (write data/add file)
#     AD (append data/add subdirectory)
#     REA (read extended attributes)
#     WEA (write extended attributes)
#     X (execute/traverse)
#     DC (delete child)
#     RA (read attributes)
#     WA (write attributes)

# canonical order when listed by icacls
ICACLS_RIGHTS_ORDER = [
    'N',
    'F',
    'M',
    'RX',
    'R',
    'W',
    'D',
    'Rc',
    'WDAC',
    'WO',
    'S',
    'AS',
    'MA',
    'GR',
    'GW',
    'GE',
    'GA',
    'RD',
    'WD',
    'AD',
    'REA',
    'WEA',
    'X',
    'DC',
    'RA',
    'WA',
]

def posix_mask_to_str(mode):
    r = ''
    r += 'S' if mode & 0o4000 else '-'
    r += 'U' if mode & 0o2000 else '-'
    r += 'G' if mode & 0o1000 else '-'
    r += ','
    r += 'r' if mode & 0o0400 else '-'
    r += 'w' if mode & 0o0200 else '-'
    r += 'x' if mode & 0o0100 else '-'
    r += ','
    r += 'r' if mode & 0o0040 else '-'
    r += 'w' if mode & 0o0020 else '-'
    r += 'x' if mode & 0o0010 else '-'
    r += ','
    r += 'r' if mode & 0o0004 else '-'
    r += 'w' if mode & 0o0002 else '-'
    r += 'x' if mode & 0o0001 else '-'
    return r

def perms_to_mask(perms):
    r = 0
    for p in perms:
        r |= ICACLS_RIGHTS[p]
    return r

def mask_to_perms(mask, include_multi=True):
    r = []
    matched = 0

    if mask == 0:
        return ['N']

    for p in ICACLS_RIGHTS_ORDER:
        pmask = ICACLS_RIGHTS[p]
        if not include_multi and p in MULTI_RIGHTS:
            continue
        if pmask != 0 and (pmask & mask) == pmask and ((~matched)&pmask) != 0:
            r.append(p)
            matched |= pmask
    return r

def icacls_sort_perms(perms):
    in_perms = set(perms)
    out_perms = []
    for p in ICACLS_RIGHTS_ORDER:
        if p in in_perms:
            out_perms.append(p)
    return out_perms

ICACLS_RIGHTS = {
    'N': 0,

    'R': SEC_RIGHTS_FILE_READ,
    'W': SEC_RIGHTS_FILE_WRITE,
    'RX': SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_EXECUTE,
    'M': SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_EXECUTE|SEC_RIGHTS_FILE_WRITE|SEC_STD_DELETE,
    'F': SEC_STD_ALL | SEC_FILE_ALL,

    'D': SEC_STD_DELETE,
    'Rc': SEC_STD_READ_CONTROL,
    'WDAC': SEC_STD_WRITE_DAC,
    'WO': SEC_STD_WRITE_OWNER,
    'S': SEC_STD_SYNCHRONIZE,
    'AS': SEC_FLAG_SYSTEM_SECURITY,
    'MA': SEC_FLAG_MAXIMUM_ALLOWED,
    'GR': SEC_GENERIC_READ,
    'GW': SEC_GENERIC_WRITE,
    'GE': SEC_GENERIC_EXECUTE,
    'GA': SEC_GENERIC_ALL,
    'RD': SEC_FILE_READ_DATA,
    'WD': SEC_FILE_WRITE_DATA,
    'AD': SEC_FILE_APPEND_DATA,
    'REA': SEC_FILE_READ_EA,
    'WEA': SEC_FILE_WRITE_EA,
    'X': SEC_FILE_EXECUTE,
    'DC': SEC_DIR_DELETE_CHILD,
    'RA': SEC_DIR_READ_ATTRIBUTE,
    'WA': SEC_DIR_WRITE_ATTRIBUTE,

}


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


# SANITY CHECKS
MULTI_RIGHTS = set(['R', 'W', 'RX', 'F', 'M'])
for a in ICACLS_RIGHTS.keys():
    va = ICACLS_RIGHTS[a]
    for b in ICACLS_RIGHTS.keys():
        vb = ICACLS_RIGHTS[b]
        if a==b:
            continue
        if va==vb:
            print("%s and %s == 0x%06x"%(a,b,va))
        elif va&vb != 0 and set([a,b]).isdisjoint(MULTI_RIGHTS):
            print("%4s (0x%06x) overlaps with %4s (0x%06x) == 0x%06x"%(a,va,b,vb,va&vb))

if __name__ == '__main__':
    main()

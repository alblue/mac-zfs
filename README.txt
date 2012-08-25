About MacZFS 
============

MacZFS is a community effort hosted on www.maczfs.org to prolong 
the life of ZFS on Mac OS X, since the Apple Open Source project 
was shut down. It is supported on both Leopard (Intel/PPC) and 
Snow Leopard (Intel 32-bit and 64-bit)platforms, including newer 
releases up to Mountain Lion.


Getting involved
================

The MacZFS community welcomes everyone who wants to share thoughts, 
opinions or success stories or wants to contribute to the project's
further development.

Discussion of use cases, user-to-user help and future development takes 
place on our mailing list hosted at http://groups.google.com/group/zfs-macos/

Problem reports and feature requests should be submitted to the issue 
tracker at http://code.google.com/p/maczfs/

If you want to help with development, the source code is available on 
Github at http://github.com/alblue/mac-zfs 

Resources:
Source: http://github.com/alblue/mac-zfs
Issues: http://code.google.com/p/maczfs/
Groups: http://groups.google.com/group/zfs-macos/
IRC:  http://webchat.freenode.net/ , select a nick name and enter channel #mac-zfs


Backups
=======

Please note that all software is known to contain bugs. Whilst care
has been taken to ensure that under normal operations things don't
go wrong, there's no guarantee of that fact. Using kernel extensions
introduce a degree of instability into a system that userland 
processes don't encounter; the software has been known to cause
kernel panics in the past. In addition, any file system has the
possibility of causing damage to files; whilst ZFS creates checksums
of all blocks (and so can detect failure earlier than in other systems)
there's no guarantee that your data will be accessible in the event
of problems. You should therefore take full responsiblity of backups
of data in the event that a restoration is needed. Any single filing
system, including ZFS, is not a substitute for backups.


Disclaimer
==========

The Original Code and all software distributed under the License are
distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
Please see the License for the specific language governing rights and
limitations under the License.


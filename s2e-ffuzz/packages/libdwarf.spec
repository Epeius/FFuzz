Summary: libdwarf library
Name: libdwarf
Version: 1.0s2e
Release: 1
License: GPL
Group: Applications/System
BuildArch: x86_64

%description
libdwarf library

%prep

%build
cd $RPM_BUILD_ROOT/..
./configure
make

%install
cd $RPM_BUILD_ROOT
mkdir -p "$RPM_BUILD_ROOT/usr/lib64"
mkdir -p "$RPM_BUILD_ROOT/usr/include"
cp $RPM_BUILD_ROOT/../libdwarf/libdwarf.a $RPM_BUILD_ROOT/usr/lib64/
cp $RPM_BUILD_ROOT/../libdwarf/libdwarf.h $RPM_BUILD_ROOT/usr/include/

%clean
cd $RPM_BUILD_ROOT/..
make distclean

%files
%defattr(-,root,root)
%doc

/usr/include/libdwarf.h
/usr/lib64/libdwarf.a

%changelog

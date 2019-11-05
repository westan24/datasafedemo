create user TEST identified by Welcome_12345;
grant DWROLE to TEST;
revoke DWROLE from TEST;
drop user TEST cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 100;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 100;
alter system set AUDIT_TRAIL=xml scope=spfile;

create user TEST1 identified by Welcome_12345;
grant DWROLE to TEST1;
revoke DWROLE from TEST1;
drop user TEST1 cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 110;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 110;
alter system set AUDIT_TRAIL=xml scope=spfile;

create user TEST2 identified by Welcome_12345;
grant DWROLE to TEST2;
revoke DWROLE from TEST2;
drop user TEST2 cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 120;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 120;
alter system set AUDIT_TRAIL=xml scope=spfile;

create user TEST3 identified by Welcome_12345;
grant DWROLE to TEST3;
revoke DWROLE from TEST3;
drop user TEST3 cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 130;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 130;
alter system set AUDIT_TRAIL=xml scope=spfile;

create user TEST4 identified by Welcome_12345;
grant DWROLE to TEST4;
revoke DWROLE from TEST4;
drop user TEST4 cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 140;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 140;
alter system set AUDIT_TRAIL=xml scope=spfile;

create user TEST5 identified by Welcome_12345;
grant DWROLE to TEST5;
revoke DWROLE from TEST5;
drop user TEST5 cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 150;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 150;
alter system set AUDIT_TRAIL=xml scope=spfile;

create user TEST6 identified by Welcome_12345;
grant DWROLE to TEST6;
revoke DWROLE from TEST6;
drop user TEST6 cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 160;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 160;
alter system set AUDIT_TRAIL=xml scope=spfile;

create user TEST7 identified by Welcome_12345;
grant DWROLE to TEST7;
revoke DWROLE from TEST7;
drop user TEST7 cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 170;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 170;
alter system set AUDIT_TRAIL=xml scope=spfile;

create user TEST8 identified by Welcome_12345;
grant DWROLE to TEST8;
revoke DWROLE from TEST8;
drop user TEST8 cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 180;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 180;
alter system set AUDIT_TRAIL=xml scope=spfile;

create user TEST9 identified by Welcome_12345;
grant DWROLE to TEST9;
revoke DWROLE from TEST9;
drop user TEST9 cascade;
update DEMO.EMPLOYEES set SALARY = 6666 where EMPLOYEE_ID = 190;
select * from DEMO.EMPLOYEES where EMPLOYEE_ID = 190;
alter system set AUDIT_TRAIL=xml scope=spfile;

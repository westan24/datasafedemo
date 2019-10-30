Rem
Rem Copyright (c) 2019, Oracle and/or its affiliates.
Rem All rights reserved.
Rem
Rem    NAME
Rem      dscs_privileges.sql
Rem
Rem    DESCRIPTION
Rem      This script contains grant/revoke privileges for audit collection/audit setting/data discovery
Rem      /data masking/assessment that are needed to setup a user.
Rem      This script should be run by SYS user
Rem      This script takes in 4 parameters:
Rem         1. username (case sensitive matching the username from dba_users. For cases with single quote,
Rem            please enter with another quote. Ex: O''Brien)
Rem         2. type (grant/revoke)
Rem         3. mode (audit_collection/audit_setting/data_discovery/masking/assessment/all)
Rem         4. -VERBOSE will only show the actual grant/revoke commands. This is optional.
Rem      To run the script 
Rem         @dscs_privileges.sql <username> <GRANT/REVOKE> <AUDIT_COLLECTION/AUDIT_SETTING/DATA_DISCOVERY/MASKING/ASSESSMENT/ALL> [-VERBOSE]
Rem
Rem    WARNING
Rem      If you are running the revoke functionality of this script on existing user, it could revoke 
Rem      existing privileges granted to the user. You will have to manually grant them back to the 
Rem      user. 
Rem      If you are revoking privileges for a specific feature, overlapping privileges would be 
Rem      revoked, you will need to grant the privileges back for the features you still want to use.
Rem
 
WHENEVER SQLERROR EXIT;


SET VERIFY OFF
SET FEEDBACK OFF
SET SERVEROUTPUT ON FORMAT WRAPPED

set termout on
prompt Enter value for USERNAME (case sensitive matching the username from dba_users)
set termout off
define user = &1
set termout on
prompt Setting USERNAME to &user

prompt Enter value for TYPE (grant/revoke)
set termout off
define type = &2
set termout on
prompt Setting TYPE to &type

prompt Enter value for MODE (audit_collection/audit_setting/data_discovery/masking/assessment/all)
set termout off
define mode = &3
set termout on
prompt Setting MODE to &mode

-- The last parameter is optional
column 4 new_value 4 noprint
select '' "4" from dual where rownum = 0;
define verbose = &4 "default"
 
DECLARE
  ver        VARCHAR2(30);
  username   VARCHAR2(128);
  v_user     VARCHAR2(128);
  v_type     VARCHAR2(6);
  v_mode     VARCHAR2(20);
  v_code     NUMBER;
  v_errm     VARCHAR2(64);
  v_verbose  VARCHAR2(8);
  priv_type  VARCHAR2(10);
  pkgcount   PLS_INTEGER;
  v_stmt     VARCHAR2(256);
  v_isPureUnified   VARCHAR2(10);
  usage_string   CONSTANT VARCHAR(128) := '@dscs_privileges.sql <username> <GRANT/REVOKE> <AUDIT_COLLECTION/AUDIT_SETTING/DATA_DISCOVERY/MASKING/ASSESSMENT/ALL> [-VERBOSE]';
  role_prefix VARCHAR2(10) := 'ORA_DSCS_';
  role_name VARCHAR2(128);
  role_exist NUMBER;
  v_role     VARCHAR2(64);
  v_tableSpace VARCHAR2(30);
  v_targetType VARCHAR2(30);
  v_warning VARCHAR(200) := null;
  v_assessWarning VARCHAR(500) := null;

  -- Procedure to execute sql statements in this script
  PROCEDURE execute_stmt(sql_stmt VARCHAR2) IS
  BEGIN
     IF (v_verbose = '-VERBOSE')
     THEN
        sys.dbms_output.put_line(sql_stmt);
     END IF;

     EXECUTE IMMEDIATE sql_stmt;
  EXCEPTION  
  WHEN OTHERS THEN
  -- privilege/role not grant when revoke, this is fine
  IF (SQLCODE = -1927 OR SQLCODE = -1951 OR SQLCODE = -1952)
  THEN
    RETURN;
  ELSE
    RAISE;
  END IF;
  END;

  PROCEDURE create_role(feature_name VARCHAR2) IS
  BEGIN
    role_name := role_prefix || feature_name;
    execute immediate 'select count(*) from SYS.DBA_ROLES where role = :1'
            into role_exist using role_name;
    IF (role_exist = 0)
    THEN
      execute_stmt('CREATE ROLE ' || role_name);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    v_code := SQLCODE;
    IF (v_code = -1921) 
    THEN
  	  null;
  	  --sys.dbms_output.put_line('Role '||role_name ||' exists');
  	ELSE RAISE;
  	END IF;
    END;

  -- Procedure to check if pure unified auditing
  PROCEDURE check_if_pure_unified(v_isPureUnified OUT VARCHAR2) AS
  BEGIN
    EXECUTE IMMEDIATE 'select upper(value) from v$option where parameter = :1'
            into v_isPureUnified using 'Unified Auditing';
    IF (v_isPureUnified is null)
    THEN
        v_isPureUnified := 'FALSE';
    END IF;
  EXCEPTION
  WHEN OTHERS THEN
    v_isPureUnified := 'FALSE';
  END;

  -- Procedure to check if DV is enabled and running corresponding privilege
  PROCEDURE execute_dv(type VARCHAR2, username VARCHAR2, v_mode VARCHAR2, v_warning VARCHAR2) IS
     dv   VARCHAR2(10);
  BEGIN
   
   EXECUTE IMMEDIATE 'SELECT upper(value) FROM v$option where parameter = :1'
           into dv using 'Oracle Database Vault';
 
   IF (dv = 'TRUE')
   THEN
      sys.dbms_output.put_line('*NOTE*');
      sys.dbms_output.put_line('======');
      sys.dbms_output.new_line();
      sys.dbms_output.put_line('The target has the Database Vault option enabled.');
      sys.dbms_output.new_line();
      sys.dbms_output.put_line('Connect to the secured target database as DV Owner and execute:');
      sys.dbms_output.new_line();

      IF (type = 'GRANT')
      THEN
          IF (v_mode = 'AUDIT_COLLECTION')
          THEN
              sys.dbms_output.put_line('GRANT DV_MONITOR to '||username||';');
          END IF;
          IF (v_mode = 'ASSESSMENT')
          THEN
              sys.dbms_output.put_line('GRANT DV_SECANALYST to '||username||';');
              IF (v_warning is not null)
              THEN
                sys.dbms_output.put_line(v_warning);             
              END IF;
          END IF;
      END IF;
      IF (type = 'REVOKE')
      THEN
          IF (v_mode = 'AUDIT_COLLECTION')
          THEN
             sys.dbms_output.put_line('REVOKE DV_MONITOR from '||username||';');
          END IF;
          IF (v_mode = 'ASSESSMENT')
          THEN
              sys.dbms_output.put_line('REVOKE DV_SECANALYST from '||username||';');
          END IF;
      END IF;
      sys.dbms_output.new_line();
   END IF;

   EXCEPTION
    WHEN OTHERS THEN
    IF (SQLCODE != -1403 AND SQLCODE != 100) -- No data found
    THEN
      RAISE;
    END IF;
  END;
     
BEGIN
   BEGIN
      v_user := '&user';
      v_type := upper('&type');
      v_mode := upper('&mode');
      v_verbose := upper('&verbose');
   EXCEPTION
      WHEN VALUE_ERROR THEN
      -- This might occur when the user specifies arguments longer than anticipated
         sys.dbms_output.put_line('ERROR: Please run the script with these parameters: ');
         sys.dbms_output.put_line(usage_string);
         sys.dbms_output.put_line('');
         sys.dbms_output.put_line('');
         return;
   END;
         

   IF (v_user is null)
   THEN
      sys.dbms_output.put_line('ERROR: Argument #1 Username must not be null');
      sys.dbms_output.put_line('ERROR: Please run the script with these parameters: ');
      sys.dbms_output.put_line(usage_string);
      sys.dbms_output.put_line('');
      sys.dbms_output.put_line('');
      return;
   END IF; 

   IF (v_type!='GRANT' and v_type!='REVOKE' or v_type is null)
   THEN
      sys.dbms_output.put_line('ERROR: Invalid argument #2 Type: ' || v_type);
      sys.dbms_output.put_line('ERROR: Please run the script with these parameters: ');
      sys.dbms_output.put_line(usage_string);
      sys.dbms_output.put_line('');
      sys.dbms_output.put_line('');
      return;
   END IF;
 
   IF (v_mode !='AUDIT_COLLECTION' and v_mode !='AUDIT_SETTING'
      AND v_mode != 'DATA_DISCOVERY' AND v_mode != 'MASKING'
      AND v_mode != 'ASSESSMENT' AND v_mode != 'ALL' or v_mode is null)
   THEN
      sys.dbms_output.put_line('ERROR: Invalid argument #3 Mode:' || v_mode);
      sys.dbms_output.put_line('ERROR: Please run the script with these parameters: ');
      sys.dbms_output.put_line(usage_string);
      sys.dbms_output.put_line('');
      sys.dbms_output.put_line('');
      return;
   END IF;

   -- set the nls_numeric_characters to '.,' as version checking fails when nls is set to germany
   EXECUTE IMMEDIATE 'ALTER SESSION SET NLS_NUMERIC_CHARACTERS = ''.,''';

   -- check if the db is pure unified auditing
   check_if_pure_unified(v_isPureUnified);

   EXECUTE IMMEDIATE 'SELECT version FROM v$instance where regexp_like(version, ''[0-9]?[0-9].[0-9].[0-9].[0-9].[0-9]'')' into ver;  

   -- throwing error message for all modes for the unsupported db versions i.e versions < 12.1.0.0
   IF(ver < '12.1%')
   THEN
      sys.dbms_output.put_line('ERROR: Oracle DB Version '||ver||' is not supported');
      sys.dbms_output.put_line('');
      sys.dbms_output.put_line('');
      return;
   END IF;
   
   --sanitizing the user input before revoking the privileges
   username := sys.dbms_assert.enquote_name(v_user, FALSE);

   IF (v_mode ='AUDIT_COLLECTION' OR v_mode = 'ALL')
   THEN
        IF(ver < '11.2%' or ver >= '20%' )
	THEN
            sys.dbms_output.put_line('ERROR: Oracle DB Version '||ver||' is not supported');
            sys.dbms_output.put_line('');
            sys.dbms_output.put_line('');
            return;
	END IF;
	IF (ver >= '12.1.0.2%')
	THEN
            priv_type := 'READ';
	ELSE
            priv_type := 'SELECT';
	END IF;
        v_role := role_prefix || 'AUDIT_COLLECTION';
		
	IF (v_type = 'GRANT')
	THEN
            sys.dbms_output.put_line('Granting AUDIT_COLLECTION privileges to '|| username ||' ... ');
            create_role('AUDIT_COLLECTION');
            
            execute_stmt('GRANT CREATE SESSION to ' || v_role);

       	    IF (ver >= '12.1%')
	    THEN
                execute_stmt('GRANT AUDIT_VIEWER TO '||v_role);
            END IF;

            IF (v_isPureUnified = 'FALSE')
            THEN
                execute_stmt('GRANT ' || priv_type || ' ON SYS.AUD$ to '|| v_role);
                execute_stmt('GRANT ' || priv_type || ' ON SYS.FGA_LOG$ to '|| v_role);
            END IF;
            execute_stmt('GRANT ' || priv_type || ' ON SYS.DBA_AUDIT_MGMT_CLEANUP_JOBS to '|| v_role);
	    execute_stmt('GRANT ' || priv_type || ' ON SYS.V_$PWFILE_USERS to '|| v_role);
	    execute_stmt('GRANT ' || priv_type || ' ON SYS.ALL_USERS to '|| v_role);
            execute_stmt('GRANT ' || priv_type || ' ON SYS.DBA_ROLES to '|| v_role);
            execute_stmt('GRANT ' || priv_type || ' ON SYS.DBA_SYS_PRIVS to '|| v_role);
            execute_stmt('GRANT ' || priv_type || ' ON SYS.DBA_ROLE_PRIVS to '|| v_role);

            IF (ver >= '18%')
            THEN
                execute_stmt('GRANT EXECUTE ON AUDSYS.DBMS_AUDIT_MGMT to '|| v_role);
            ELSE
		execute_stmt('GRANT EXECUTE ON SYS.DBMS_AUDIT_MGMT to '|| v_role);
            END IF;
            execute_stmt('GRANT ' || v_role || ' to '|| username);
	END IF;
	IF (v_type = 'REVOKE')
	THEN
            sys.dbms_output.put_line('Revoking AUDIT_COLLECTION privileges from '|| username ||' ... ');            
            execute_stmt('REVOKE ' || v_role || ' FROM '||username);
           
	END IF;
    END IF;

    IF (v_mode ='AUDIT_SETTING' OR v_mode = 'ALL')
    THEN
       IF (ver < '12.1.0.2%' or ver >= '20%' )
       THEN
          sys.dbms_output.put_line('ERROR: Oracle DB Version '||ver||' is not supported');
          sys.dbms_output.put_line('');
          sys.dbms_output.put_line('');
          return;
       END IF;
       v_role := role_prefix || 'AUDIT_SETTING';
	   IF (v_type = 'GRANT')
	   THEN
		   sys.dbms_output.put_line('Granting AUDIT_SETTING privileges to '|| username ||' ... ');
                   create_role('AUDIT_SETTING');
		   execute_stmt('GRANT CREATE SESSION  to '|| v_role);
                   execute_stmt('GRANT AUDIT_ADMIN TO '|| v_role);
                   execute_stmt('GRANT ' || v_role || ' to '|| username);
	   END IF;
	   IF (v_type = 'REVOKE')
	   THEN
		   sys.dbms_output.put_line('Revoking AUDIT_SETTING privileges from '|| username ||' ... ');
		   execute_stmt('REVOKE ' || v_role || ' FROM '||username);                   
	   END IF;
    END IF;
 
    IF (v_mode ='DATA_DISCOVERY' OR v_mode = 'ALL')
    THEN
       IF (ver >= '12.1.0.2%')
       THEN
           priv_type := 'READ';
       ELSE
           priv_type := 'SELECT';
       END IF;

       IF (v_type = 'GRANT')
          THEN
                 sys.dbms_output.put_line('Granting DATA_DISCOVERY role to '|| username ||' ... ');
                 create_role('DATA_DISCOVERY');
                 execute_stmt('GRANT CREATE SESSION TO ' || role_prefix || 'DATA_DISCOVERY');
                 execute_stmt('GRANT ' || priv_type || ' ANY TABLE TO ' || role_prefix || 'DATA_DISCOVERY');
                 execute_stmt('GRANT CREATE PROCEDURE TO '|| role_prefix || 'DATA_DISCOVERY');
                 execute_stmt('GRANT ' || priv_type || ' ON SYS.V_$DATABASE TO ' || role_prefix || 'DATA_DISCOVERY');
                 -- grant role to user
                 execute_stmt('GRANT ' || role_prefix || 'DATA_DISCOVERY to '|| username);
       END IF;
       IF (v_type = 'REVOKE')
          THEN
                 sys.dbms_output.put_line('Revoking DATA_DISCOVERY role from '|| username ||' ... ');
                 execute_stmt('REVOKE ' || role_prefix || 'DATA_DISCOVERY FROM '||username);
        END IF;
    END IF;

    IF (v_mode ='MASKING' OR v_mode = 'ALL')
    THEN
       IF (v_type = 'GRANT')
          THEN
                 sys.dbms_output.put_line('Granting MASKING role to '|| username ||' ... ');
                 EXECUTE IMMEDIATE ('select DEFAULT_TABLESPACE from 
					SYS.DBA_USERS where USERNAME = :1') into v_tableSpace 
                  using v_user;
                 IF (v_tableSpace = 'SYSTEM' OR v_tableSpace = 'SYSAUX')
                 THEN
                     v_warning := 'WARNING : Default tablespace of the user is SYSTEM/SYSAUX.'||
                     ' Masking job by users with either of these as default tablespace will fail.';
                 END IF;
                 
                 -- Check the target type
                 BEGIN
                    EXECUTE IMMEDIATE ('select sys_context (''USERENV'', ''CLOUD_SERVICE'') from sys.dual') into v_targetType;
                 EXCEPTION
                 -- ignore exceptions
                    WHEN OTHERS THEN
                    NULL;
                 END;
                 
                 create_role('MASKING');
                 execute_stmt('GRANT CREATE SESSION TO ' || role_prefix || 'MASKING');
                 -- *** SELECT_CATALOG_ROLE Required for DBMS_METADATA call
                 execute_stmt('GRANT SELECT_CATALOG_ROLE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT SELECT ANY TABLE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT CREATE ANY PROCEDURE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT DROP ANY PROCEDURE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT EXECUTE ANY PROCEDURE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT ANALYZE ANY TO ' || role_prefix || 'MASKING');
                 
                 -- Dont grant alter system for cloud targets 
                 IF v_targetType is null OR upper(v_targetType) NOT IN ('OLTP', 'PAAS', 'DWCS') THEN
                 	execute_stmt('GRANT ALTER SYSTEM TO ' || role_prefix || 'MASKING');
                 END IF;
                 execute_stmt('GRANT CREATE TYPE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT CREATE ANY TABLE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT INSERT ANY TABLE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT LOCK ANY TABLE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT ALTER ANY TABLE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT DROP ANY TABLE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT UPDATE ANY TABLE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT CREATE ANY INDEX TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT DROP ANY INDEX TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT ALTER ANY INDEX TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT COMMENT ANY TABLE TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT CREATE ANY TRIGGER TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT DROP ANY TRIGGER TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT ALTER ANY TRIGGER TO ' || role_prefix || 'MASKING');

                 -- Required for deterministic mask
                 execute_stmt('GRANT CREATE ANY CONTEXT TO ' || role_prefix || 'MASKING');
                 execute_stmt('GRANT DROP ANY CONTEXT TO ' || role_prefix || 'MASKING');

                 -- Direct grants required since roles are turned off during
                 -- pl/sql code compilation. Our deploy will fail without this.
                 execute_stmt('GRANT EXECUTE ON SYS.DBMS_CRYPTO TO ' ||username);
                 execute_stmt('GRANT EXECUTE ON SYS.UTL_RECOMP TO ' || username);
                 execute_stmt('GRANT UNLIMITED TABLESPACE TO '||username);

                 -- grant role to user
                 execute_stmt('GRANT ' || role_prefix || 'MASKING to '|| username);
       END IF;
       IF (v_type = 'REVOKE')
          THEN
                 sys.dbms_output.put_line('Revoking MASKING role from '|| username ||' ... ');
                 execute_stmt('REVOKE UNLIMITED TABLESPACE from '||username);
                 execute_stmt('REVOKE ' || role_prefix || 'MASKING FROM '||username);
                 execute_stmt('REVOKE EXECUTE ON SYS.DBMS_CRYPTO FROM ' ||username);
                 execute_stmt('REVOKE EXECUTE ON SYS.UTL_RECOMP FROM ' || username);
                 execute_stmt('REVOKE UNLIMITED TABLESPACE FROM '||username);
        END IF;
    END IF;

    IF (v_mode ='ASSESSMENT' OR v_mode = 'ALL')
    THEN
       IF (ver >= '12.1.0.2%')
          THEN
                 priv_type := 'READ';
       ELSE
                 priv_type := 'SELECT';
       END IF;
       
       IF (v_type = 'GRANT')
          THEN
                 sys.dbms_output.put_line('Granting ASSESSMENT role to '|| username ||' ... ');
                 create_role('ASSESSMENT');
                 execute_stmt('GRANT CREATE SESSION TO '|| role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_REGISTRY_SQLPATCH  TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_ROLES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_ROLE_PRIVS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_SYS_PRIVS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_TAB_PRIVS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_TABLES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_COL_PRIVS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_USERS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_PROFILES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_DIRECTORIES  TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_DB_LINKS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_DATA_FILES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_TRIGGERS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_POLICIES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_SENSITIVE_DATA TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_TSDP_POLICY_FEATURE TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_ENCRYPTED_COLUMNS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_LIBRARIES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_NETWORK_ACLS  TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_NETWORK_ACL_PRIVILEGES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_STMT_AUDIT_OPTS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_OBJ_AUDIT_OPTS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_PRIV_AUDIT_OPTS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_AUDIT_POLICIES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_AUDIT_TRAIL TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_FGA_AUDIT_TRAIL TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_XS_POLICIES  TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_XS_APPLIED_POLICIES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_XS_ACES TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_CONSTRAINTS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.V_$INSTANCE TO ' || role_prefix || 'ASSESSMENT');
				 execute_stmt('GRANT '||priv_type||' ON SYS.V_$PWFILE_USERS TO ' || role_prefix || 'ASSESSMENT');
                 execute_stmt('GRANT '||priv_type||' ON SYS.DBA_TAB_COLUMNS TO ' || role_prefix || 'ASSESSMENT');
                 BEGIN
                   execute_stmt('GRANT '||priv_type||' ON SYS.DBA_JAVA_POLICY TO ' || role_prefix || 'ASSESSMENT');
                   execute_stmt('GRANT '||priv_type||' ON SYS.REGISTRY$HISTORY TO '|| role_prefix || 'ASSESSMENT');
                   execute_stmt('GRANT '||priv_type||' ON SYS.DBA_USERS_WITH_DEFPWD TO '|| role_prefix || 'ASSESSMENT');
                   execute_stmt('GRANT '||priv_type||' ON SYS."_BASE_USER" to '|| role_prefix || 'ASSESSMENT');
                   --grants on objects not in any Default realm should be added before this.
                   execute_stmt('GRANT '||priv_type||' ON LBACSYS.DBA_SA_SCHEMA_POLICIES  TO ' || role_prefix || 'ASSESSMENT');
                   execute_stmt('GRANT '||priv_type||' ON LBACSYS.DBA_SA_TABLE_POLICIES TO ' || role_prefix || 'ASSESSMENT');
                 EXCEPTION
                   WHEN OTHERS THEN  
                       v_code := SQLCODE;
                       IF(v_code = -47401)
                       THEN
                          v_assessWarning :=  'GRANT '||priv_type||' ON LBACSYS.DBA_SA_SCHEMA_POLICIES  TO ' || role_prefix || 'ASSESSMENT'|| ';'|| chr(13) || chr(10) ||
                                              'GRANT '||priv_type||' ON LBACSYS.DBA_SA_TABLE_POLICIES TO ' || role_prefix || 'ASSESSMENT'|| ';' || chr(13) || chr(10);
                       ELSIF(v_code = -942 OR v_code = -1031)
                       THEN NULL;
                       ELSE RAISE;
                       END IF;
                 END;
                 
                 IF (ver >= '12.1%')
                 THEN
                   execute_stmt('GRANT AUDIT_VIEWER TO '|| role_prefix || 'ASSESSMENT');
                   execute_stmt('GRANT CAPTURE_ADMIN TO '|| role_prefix || 'ASSESSMENT');
                 BEGIN
                   execute_stmt('GRANT SELECT ON AUDSYS.AUD$UNIFIED TO '|| role_prefix || 'ASSESSMENT');
                 EXCEPTION
                   WHEN OTHERS THEN  
                       v_code := SQLCODE;
                       IF(v_code = -942 OR v_code = -1031)
                       THEN NULL;
                       ELSE RAISE;
                       END IF;
                 END;
                 
                 END IF;
                 -- grant role to user
                 execute_stmt('GRANT ' || role_prefix || 'ASSESSMENT to '|| username);
       ELSE
                 sys.dbms_output.put_line('Revoking ASSESSMENT role from '||username||' ... ');
                 execute_stmt('REVOKE ' || role_prefix || 'ASSESSMENT FROM '||username);
       END IF;
    END IF;   
    IF (v_warning is not null)
    THEN
      sys.dbms_output.put_line(v_warning);             
    END IF;
    sys.dbms_output.put_line('Done.');

    --run the procedure for DV
    execute_dv(v_type, username, v_mode, v_assessWarning);
EXCEPTION
  WHEN OTHERS THEN
    v_code := SQLCODE;
    v_errm := SUBSTR(SQLERRM, 1, 64);
    sys.DBMS_OUTPUT.PUT_LINE('The error code is ' || v_code);
    sys.dbms_output.put_line(v_errm);
    IF (v_code = -942)
    THEN
        sys.dbms_output.put_line('Login as SYS or PDB_ADMIN to grant privileges to the user ');
    END IF;
    IF (v_code != -1917)    -- username doesn't exists
    THEN
        sys.dbms_output.put_line('If problem persists, contact Oracle Support');
    END IF;
  
END;
/

SET FEEDBACK ON
 
EXIT;

package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Role;
import com.easybusiness.usermanagement.entity.RoleActionMap;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(RoleActionMap.class)
public abstract class RoleActionMap_ {

	public static volatile SingularAttribute<RoleActionMap, Long> selectAllowed;
	public static volatile SingularAttribute<RoleActionMap, Role> role;
	public static volatile SingularAttribute<RoleActionMap, Long> deleteAllowed;
	public static volatile SingularAttribute<RoleActionMap, Date> toDate;
	public static volatile SingularAttribute<RoleActionMap, Long> isEnable;
	public static volatile SingularAttribute<RoleActionMap, Date> fromDate;
	public static volatile SingularAttribute<RoleActionMap, Long> uploadAllowed;
	public static volatile SingularAttribute<RoleActionMap, Date> modifiedOn;
	public static volatile SingularAttribute<RoleActionMap, Long> createAllowed;
	public static volatile SingularAttribute<RoleActionMap, String> modifiedBy;
	public static volatile SingularAttribute<RoleActionMap, Long> downloadAllowed;
	public static volatile SingularAttribute<RoleActionMap, Long> id;
	public static volatile SingularAttribute<RoleActionMap, Long> updateAllowed;
	public static volatile SingularAttribute<RoleActionMap, Long> printAllowed;
	public static volatile SingularAttribute<RoleActionMap, Long> viewAllowed;

}


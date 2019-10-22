package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Role;
import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserRoleMap;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(UserRoleMap.class)
public abstract class UserRoleMap_ {

	public static volatile SingularAttribute<UserRoleMap, Date> fromDate;
	public static volatile SingularAttribute<UserRoleMap, Date> modifiedOn;
	public static volatile SingularAttribute<UserRoleMap, Role> role;
	public static volatile SingularAttribute<UserRoleMap, Date> toDate;
	public static volatile SingularAttribute<UserRoleMap, String> modifiedBy;
	public static volatile SingularAttribute<UserRoleMap, Long> id;
	public static volatile SingularAttribute<UserRoleMap, User> user;
	public static volatile SingularAttribute<UserRoleMap, Long> isEnable;

}


package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserGroup;
import com.easybusiness.usermanagement.entity.UserGroupMap;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(UserGroupMap.class)
public abstract class UserGroupMap_ {

	public static volatile SingularAttribute<UserGroupMap, Date> fromDate;
	public static volatile SingularAttribute<UserGroupMap, Date> modifiedOn;
	public static volatile SingularAttribute<UserGroupMap, Date> toDate;
	public static volatile SingularAttribute<UserGroupMap, String> modifiedBy;
	public static volatile SingularAttribute<UserGroupMap, Long> id;
	public static volatile SingularAttribute<UserGroupMap, UserGroup> userGroup;
	public static volatile SingularAttribute<UserGroupMap, User> user;
	public static volatile SingularAttribute<UserGroupMap, Long> isEnable;

}


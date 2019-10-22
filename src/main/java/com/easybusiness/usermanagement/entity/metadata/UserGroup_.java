package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.UserGroup;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(UserGroup.class)
public abstract class UserGroup_ {

	public static volatile SingularAttribute<UserGroup, Date> fromDate;
	public static volatile SingularAttribute<UserGroup, Date> modifiedOn;
	public static volatile SingularAttribute<UserGroup, String> userGroupName;
	public static volatile SingularAttribute<UserGroup, Date> toDate;
	public static volatile SingularAttribute<UserGroup, String> modifiedBy;
	public static volatile SingularAttribute<UserGroup, Long> id;
	public static volatile SingularAttribute<UserGroup, Long> isEnable;

}


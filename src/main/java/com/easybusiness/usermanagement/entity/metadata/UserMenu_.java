package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Menu;
import com.easybusiness.usermanagement.entity.UserGroupMap;
import com.easybusiness.usermanagement.entity.UserMenu;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(UserMenu.class)
public abstract class UserMenu_ {

	public static volatile SingularAttribute<UserMenu, UserGroupMap> userGroupMap;
	public static volatile SingularAttribute<UserMenu, Date> fromDate;
	public static volatile SingularAttribute<UserMenu, Date> modifiedOn;
	public static volatile SingularAttribute<UserMenu, Date> toDate;
	public static volatile SingularAttribute<UserMenu, String> modifiedBy;
	public static volatile SingularAttribute<UserMenu, Long> id;
	public static volatile SingularAttribute<UserMenu, Menu> menuItem;
	public static volatile SingularAttribute<UserMenu, Long> isEnable;

}


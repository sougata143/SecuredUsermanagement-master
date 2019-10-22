package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Menu;
import com.easybusiness.usermanagement.entity.SubMenu;
import com.easybusiness.usermanagement.entity.UserGroup;
import com.easybusiness.usermanagement.entity.UserGroupMenuSubMenu;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(UserGroupMenuSubMenu.class)
public abstract class UserGroupMenuSubMenu_ {

	public static volatile SingularAttribute<UserGroupMenuSubMenu, Date> fromDate;
	public static volatile SingularAttribute<UserGroupMenuSubMenu, Date> modifiedOn;
	public static volatile SingularAttribute<UserGroupMenuSubMenu, Date> toDate;
	public static volatile SingularAttribute<UserGroupMenuSubMenu, SubMenu> subMenuItem;
	public static volatile SingularAttribute<UserGroupMenuSubMenu, String> modifiedBy;
	public static volatile SingularAttribute<UserGroupMenuSubMenu, Long> id;
	public static volatile SingularAttribute<UserGroupMenuSubMenu, Menu> menuItem;
	public static volatile SingularAttribute<UserGroupMenuSubMenu, UserGroup> userGroup;
	public static volatile SingularAttribute<UserGroupMenuSubMenu, Long> isEnable;

}


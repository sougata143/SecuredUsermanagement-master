package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Menu;
import com.easybusiness.usermanagement.entity.SubMenu;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(SubMenu.class)
public abstract class SubMenu_ {

	public static volatile SingularAttribute<SubMenu, Date> modifiedTime;
	public static volatile SingularAttribute<SubMenu, String> subMenu;
	public static volatile SingularAttribute<SubMenu, String> modifiedBy;
	public static volatile SingularAttribute<SubMenu, Long> id;
	public static volatile SingularAttribute<SubMenu, Menu> menu;

}


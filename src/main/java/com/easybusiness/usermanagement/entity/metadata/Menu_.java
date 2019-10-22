package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Menu;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Menu.class)
public abstract class Menu_ {

	public static volatile SingularAttribute<Menu, Date> modifiedTime;
	public static volatile SingularAttribute<Menu, String> menuName;
	public static volatile SingularAttribute<Menu, String> modifiedBy;
	public static volatile SingularAttribute<Menu, Long> id;
	public static volatile SingularAttribute<Menu, String> menuIconName;

}


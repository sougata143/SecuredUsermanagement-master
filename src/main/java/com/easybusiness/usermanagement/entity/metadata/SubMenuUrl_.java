package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.SubMenu;
import com.easybusiness.usermanagement.entity.SubMenuUrl;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(SubMenuUrl.class)
public abstract class SubMenuUrl_ {

	public static volatile SingularAttribute<SubMenuUrl, SubMenu> subMenu;
	public static volatile SingularAttribute<SubMenuUrl, String> createdBy;
	public static volatile SingularAttribute<SubMenuUrl, Long> id;
	public static volatile SingularAttribute<SubMenuUrl, Date> createdOn;
	public static volatile SingularAttribute<SubMenuUrl, String> url;

}


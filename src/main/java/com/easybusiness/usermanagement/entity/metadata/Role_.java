package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Role;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Role.class)
public abstract class Role_ {

	public static volatile SingularAttribute<Role, Date> fromDate;
	public static volatile SingularAttribute<Role, Date> modifiedOn;
	public static volatile SingularAttribute<Role, String> role;
	public static volatile SingularAttribute<Role, Date> toDate;
	public static volatile SingularAttribute<Role, String> modifiedBy;
	public static volatile SingularAttribute<Role, Long> id;
	public static volatile SingularAttribute<Role, Long> isEnable;

}


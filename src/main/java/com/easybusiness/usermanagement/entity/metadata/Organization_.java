package com.easybusiness.usermanagement.entity.metadata;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Organization;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Organization.class)
public abstract class Organization_ {

	public static volatile SingularAttribute<Organization, String> orgName;
	public static volatile SingularAttribute<Organization, String> orgLocation;
	public static volatile SingularAttribute<Organization, Long> id;

}


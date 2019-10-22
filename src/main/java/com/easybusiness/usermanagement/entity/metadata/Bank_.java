package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Bank;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Bank.class)
public abstract class Bank_ {

	public static volatile SingularAttribute<Bank, Date> modifiedOn;
	public static volatile SingularAttribute<Bank, String> address;
	public static volatile SingularAttribute<Bank, String> bankName;
	public static volatile SingularAttribute<Bank, String> location;
	public static volatile SingularAttribute<Bank, String> modifiedBy;
	public static volatile SingularAttribute<Bank, Long> id;

}


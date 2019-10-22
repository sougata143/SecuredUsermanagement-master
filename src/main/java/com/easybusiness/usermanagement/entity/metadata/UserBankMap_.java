package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.Bank;
import com.easybusiness.usermanagement.entity.Branch;
import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserBankMap;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(UserBankMap.class)
public abstract class UserBankMap_ {

	public static volatile SingularAttribute<UserBankMap, Bank> bank;
	public static volatile SingularAttribute<UserBankMap, Date> modifiedOn;
	public static volatile SingularAttribute<UserBankMap, String> accountNum;
	public static volatile SingularAttribute<UserBankMap, String> modifiedBy;
	public static volatile SingularAttribute<UserBankMap, Long> id;
	public static volatile SingularAttribute<UserBankMap, User> user;
	public static volatile SingularAttribute<UserBankMap, Branch> branch;
	public static volatile SingularAttribute<UserBankMap, String> ifscCode;
	public static volatile SingularAttribute<UserBankMap, String> accountType;

}


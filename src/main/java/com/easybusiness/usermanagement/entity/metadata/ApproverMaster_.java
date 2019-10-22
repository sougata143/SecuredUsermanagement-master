package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.ApproverMaster;
import com.easybusiness.usermanagement.entity.User;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(ApproverMaster.class)
public abstract class ApproverMaster_ {

	public static volatile SingularAttribute<ApproverMaster, String> taskDesc;
	public static volatile SingularAttribute<ApproverMaster, User> user1;
	public static volatile SingularAttribute<ApproverMaster, User> user2;
	public static volatile SingularAttribute<ApproverMaster, Date> modifiedOn;
	public static volatile SingularAttribute<ApproverMaster, String> modifiedBy;
	public static volatile SingularAttribute<ApproverMaster, Long> id;
	public static volatile SingularAttribute<ApproverMaster, User> user5;
	public static volatile SingularAttribute<ApproverMaster, User> user3;
	public static volatile SingularAttribute<ApproverMaster, User> user4;

}


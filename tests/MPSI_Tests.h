#pragma once 

#include "cryptoTools/Common/CLP.h"

void MPSI_3Party_Empty_Test(const oc::CLP&);
void MPSI_3Party_Partial_Test(const oc::CLP&);
void MPSI_3Party_Full_Test(const oc::CLP&);
void MPSI_3Party_Mthreads_Test(const oc::CLP&);
void MPSI_3Party_Cardinality_Test(const oc::CLP&);
void MPSI_3Party_Circuit_Test(const oc::CLP&);
void MPSI_3Party_Broadcast_Test(const oc::CLP&);
void MPSI_3Party_Malicious_Test(const oc::CLP& cmd);

void MPSI_5Party_Empty_Test(const oc::CLP&);
void MPSI_5Party_Partial_Test(const oc::CLP&);
void MPSI_5Party_Full_Test(const oc::CLP&);
void MPSI_5Party_Mthreads_Test(const oc::CLP&);
void MPSI_5Party_Cardinality_Test(const oc::CLP&);
void MPSI_5Party_Circuit_Test(const oc::CLP&);
void MPSI_5Party_Broadcast_Test(const oc::CLP&);
void MPSI_5Party_Malicious_Test(const oc::CLP& cmd);
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { EspacePatientPageRoutingModule } from './espace-patient-routing.module';

import { EspacePatientPage } from './espace-patient.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    EspacePatientPageRoutingModule
  ],
  declarations: [EspacePatientPage]
})
export class EspacePatientPageModule {}
